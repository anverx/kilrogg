#!/usr/bin/env python
# Copyright (c) 2013, Anatoli Verkhovski
""" Eye of Kilrogg """

from typing import Dict
import gi

gi.require_version("Gtk", "3.0")

from gi.repository import Gtk
from gi.repository import GLib

import time
import subprocess
import os
import logging

from net_scanner import NetScanner

# SCAN_LOOP_DELAY = 30

LOG = None  # type: logging.Logger|None
scanner = None  # type: NetScanner|None


node_state_colors = {
    'recently down': '#FFe0e0',
    'recently up':   '#e0FFe0',
    'up':            '#F0FFF0',
    'down':          '#e0e0e0',
    'awhile down':   '#f0f0f0'
}


def color_lookup(state, timestamp):
    """
    :param str state:
    :param int timestamp:
    """
    # logging.debug('State: %s, tst: %r', state, timestamp)
    if state != 'down':
        if time.time() - timestamp < 60 * 5:
            return node_state_colors['recently up']
        else:
            return node_state_colors['up']

        # LOG.debug('Host %s down: %d min', host_list[i]['name'],
        #         int(time.time()-host_list[i]['state']['tst'])/60)
    if time.time() - timestamp < 60 * 5:
        return node_state_colors['recently down']
    elif time.time() - timestamp < 60 * 60 * 5:
        return node_state_colors['down']

    return node_state_colors['awhile down']






def main():
    """ Main thread is the gui thread, in addition a networking thread is started, it scans the net for  """
    global scanner, LOG

    # logging.basicConfig()
    logging.basicConfig(format='%(asctime)s - %(levelname)s %(filename)s(%(lineno)s):%(funcName)s %(message)s',
                        level=logging.DEBUG)
    LOG = logging.getLogger('kilrogg')
    LOG.setLevel(logging.DEBUG)
    LOG.debug('starting...')   

    scanner = NetScanner()
    scanner.start()
    logging.debug('starting gtk.main')
    _ = GUI()

    try:
        Gtk.main()
        scanner.quit = True
        time.sleep(1)  # wait for nethread to terminate        
    
    finally:
        scanner.save()


def compare_dicts(dict1, dict2):
    """
    :param Dict dict1:
    :param Dict dict2:
    :rtype: bool
    """

    for key in dict1.keys():
        if key not in dict2 or dict1[key] != dict2[key]:
            logging.debug('key: %r v1: %r v2: %r', key, dict1.get(key), dict2.get(key))
            return False

    return all(key in dict1 for key in dict2.keys())

def get_name(host):
    """
    :param Dict[str,str|Dict[str,st]] host:
    :rtype: str
    """
    for name in host.get('names', []):  # pick one that is not IP
        if not name.replace('.', '').isnumeric():
            return name
    return host.get('name') or ''


class GUI(object):
    GLADE_FILE = './kilrogg.glade'

    def __init__(self):
        # self.gui = gtk.glade.XML(self.GLADE_FILE)
        self.gui = Gtk.Builder()
        self.gui.add_from_file(self.GLADE_FILE)
        self.gui.get_object('window1').connect("destroy", Gtk.main_quit)
        self.gui.get_object('window1').show_all()
        self.device_list = {}

        tview = self.gui.get_object('Hosts') # type: Gtk.TreeView
        # Host type fg color, bg color, tooltip, mac
        tview.set_model(Gtk.ListStore(str, str, str, str, str, str, int, str))
        tview.append_column(Gtk.TreeViewColumn('No', Gtk.CellRendererText(), text=6, background=3))
        tview.append_column(Gtk.TreeViewColumn('Host', Gtk.CellRendererText(), text=0, background=3))
        tview.append_column(Gtk.TreeViewColumn('Name', Gtk.CellRendererText(), text=7, background=3))
        tview.append_column(Gtk.TreeViewColumn('type', Gtk.CellRendererText(), text=1, background=3))
    
        #    ui.treeview_debug.append_column(gtk.TreeViewColumn('Value', gtk.CellRendererText(), text=1))
        #    ui.treeview_debug.append_column(gtk.TreeViewColumn('Type',  gtk.CellRendererText(), text=2))
        # for i in tview.get_columns():
        #     i.set_sizing(Gtk.TREE_VIEW_COLUMN_AUTOSIZE)
        # tv.get_model().append(('Gagaga',))
        # tv.get_model().append(('HaHaHa',))
        # mytips = MyTooltips()
        # mytips.add_view(tview)
    
        tview.connect("button-press-event", self.on_treeview_button_press_event)
        # Gtk.gtk_widget_set_tooltip_markup(tview, 'bleh?')
        tview.set_tooltip_markup('+++ bleh? +++ \n -------------')
        tview.has_tooltip = True
        tview.connect('query-tooltip', self.query_tooltip)

        tve = self.gui.get_object('Events')  # type: Gtk.TreeView
        tve.set_model(Gtk.ListStore(str, str))
        tve.append_column(Gtk.TreeViewColumn('Time',  Gtk.CellRendererText(), text=0))
        tve.append_column(Gtk.TreeViewColumn('Event', Gtk.CellRendererText(), text=1))
        # for i in tve.get_columns():
        #    i.set_sizing(Gtk.TREE_VIEW_COLUMN_AUTOSIZE)
        
#        for i in reversed(events):
#           tve.get_model().append((i.get('tst'), i.get('event') or '' +' '+i['host_name']))
            
        self.update_gui()
        GLib.timeout_add(2000, self.update_gui)  # install repaint timer

    def query_tooltip(self, *args):
        """
        params Tuple args: Tree, x, y, keyboard mode, tooltip
        """

        # logging.debug('tooltip? %r', repr(args))

        result = args[0].get_path_at_pos(args[1],args[2])

        if result is None:
            return False

        path, column, _, _ = result
        mac = args[0].get_model()[path][5]
        # logging.debug('path? %r', repr(args[0].get_model()[path][5]))
        args[4].set_markup(self.format_tooltip(scanner.host_list[mac]))

        return True

    @staticmethod
    def on_external(_, params):
        if params['command'] == 'ssh':
            os.system('xterm -e ssh ' + params['target'] + ' -l root &')
        if params['command'] == 'http':
            LOG.debug('http://' + params['target'])
            subprocess.Popen(['xdg-open', 'http://' + params['target']])

    def on_label(self, _, host):
        """ Label a host """
        self.gui.get_object('label_head1').set_markup('<b>Set custom label for host %s</b>'
                                                      % scanner.host_list[host]['name'])
        try: 
            res = self.gui.get_object('dialog_label').run()
            if res == Gtk.ResponseType.OK:
                LOG.debug('OK: label:%s, host: %s', self.gui.get_object('entry_label').get_text(),
                          str(scanner.host_list[host]))
                # TODO scanner.set_label(host)
                scanner.host_list[host]['label'] = self.gui.get_object('entry_label').get_text()
        finally:
            self.gui.get_object('dialog_label').hide()
    
    def on_treeview_button_press_event(self, treeview, event):
        """
        :param Gtk.TreeView treeview:
        :param event:  # some gtk event?
        """
        x = int(event.x)
        y = int(event.y)
        etime = event.time
        pthinfo = treeview.get_path_at_pos(x, y)
        if pthinfo is None:
            return
        path, col, cellx, celly = pthinfo
        treeview.grab_focus()
        treeview.set_cursor(path, col, 0)
        hosts_popup = Gtk.Menu()

        host = scanner.host_list[treeview.get_model()[path[0]][5]]
        logging.debug('%r', host)

        if event.button == 1:
            self.gui.get_object('lbl_info_ip').set_markup(host.get('IP') or '')
            self.gui.get_object('lbl_info_mac').set_markup(host.get('mac') or '')
            self.gui.get_object('lbl_info_macowner').set_markup(host.get('mac owner') or '')

            for name in host.get('names', []):  # pick one that is not IP
                if not name.replace('.','').isnumeric():
                    self.gui.get_object('lbl_info_name').set_markup(name)
                    break
            else:
                self.gui.get_object('lbl_info_name').set_markup(host.get('name') or '')

            self.gui.get_object('lbl_info_up_since').set_markup(time.ctime(host['state']['tst'])[4:-5])
            self.gui.get_object('lbl_info_online').set_markup(host['state'].get('state') or '')
            self.gui.get_object('entry_info_label').set_text(host.get('label') or '')
            try:
                ports = str(host['nmap']['ports'])
                self.gui.get_object('txt_info_nmap').get_buffer().set_text(ports)
            except KeyError:
                pass

        elif event.button == 3:
            mitem = Gtk.MenuItem('Label ... ')
            hosts_popup.append(mitem)
            mitem.connect("activate", self.on_label, host['mac'])
            mitem.show()

            if host.get('nmap') and host['nmap'].get('ports'):
                for i in host['nmap']['ports']:
                    if i[2] == 'ssh':
                        mi = Gtk.MenuItem('ssh as root')
                        hosts_popup.append(mi)
                        mi.connect("activate", self.on_external, {'target': host['name'], 'command': 'ssh'})
                        mi.show()
                    if i[2] == 'http':
                        mi = Gtk.MenuItem('http')
                        hosts_popup.append(mi)
                        mi.connect("activate", self.on_external, {'target': host['name'], 'command': 'http'})
                        mi.show()
#       self.popup_for_device(None, parent_menu_shell, parent_menu_item, func, data, button, activate_time)
            hosts_popup.popup(None, None, None, None, event.button, etime)
        return True

    def update_gui(self):
        """ Repaint GUI """
#        LOG.debug('update gui')

        # ======================= Events ====================================
        model = self.gui.get_object('Hosts').get_model()
#        tmp = host_list.values()
        # sorted_list = sorted(host_list.values(), key=lambda k: k['name'])

        scroll_offset = self.gui.get_object('scrolledwindow1').get_vadjustment().get_value()
        # logging.debug('Scroll offset: %d', scroll_offset)
        if compare_dicts(scanner.host_list, self.device_list):
             return True
        self.device_list = dict(scanner.host_list)

        tmp_hosts = sorted(scanner.host_list.values(), key=lambda k: k['name'])
        # if self.device_list == tmp_hosts:
        #    return True

        class_list = []
        other_list = []
        old_list = []

        for j in tmp_hosts:  # sort host list into groups
            if j['scan_tst'] < time.time() - 60*60*24*7:
                old_list.append(j)
                continue
            if j.get('node_class'):
                class_list.append(j)
                continue
            other_list.append(j)               

        model.clear()                
        count = 0
        for group_list in (sorted(class_list, key=lambda k: k['node_class']), other_list, old_list):
            for j in group_list:
                color = '#e0e0e0'
                # if j.get('state') and j['state'].get('color'):
                color = color_lookup(j['state']['state'], j['state']['tst'])
                        # j['state']['color']
                # print (repr(j))
                buf = self.format_tooltip(j)
                column2 = ''
                if j.get('label'):
                    column2 = j['label']+' '
                if j.get('node_class'):
                    column2 += '('+j.get('node_class')+')'
                if j.get('mac owner') and 'Not Found' not in j.get('mac owner'):
                    column2 += '['+j.get('mac owner')+']'
#                LOG.debug('label: %s class: %s  column2: %s', j.get('label'),j.get('node class'))
                model.append((j['IP'], column2, '#88FF88', color, buf, j['mac'], count, get_name(j)))
                count += 1


        self.gui.get_object('scrolledwindow1').get_vadjustment().set_value(scroll_offset)
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)

        # ======================= Events ====================================
        tve = self.gui.get_object('Events')  # type: Gtk.TreeView
        tve.get_model().clear()
        
        count = 0  # limit number of events shown to 200
        for i in reversed(scanner.events):
            count += 1
            if count > 200:
                break
            tve.get_model().append((time.ctime(i.get('tst'))[4:-5], (i.get('event') or '') +
                                    ' ' + i['host_name'] + ' ' + i['host_mac']))
        return True

    @staticmethod
    def format_tooltip(host):
        """ Prepare tooltip string
        :param Dict host:
        :return:
        :rtype: str
        """
        
        buf = ' MAC \t: ' + host['mac']
        buf += '\n iface\t: ' + host['iface']
        buf += '\n name\t: ' + host['name']
#        LOG.debug('host: %s', str(host))
#               s += '\n IP   \t:'
        if host.get('nmap'):
            if host['nmap']['state'] == 'down':
                buf += '\n Host is unreachable.'
            else:
                if host['nmap'].get('IP'):
                    buf += '\n IP   \t\t: ' + host['nmap']['IP'].decode("utf-8")
                if host['nmap'].get('MAC owner'):
                    buf += '\n MAC owner\t:'+host['nmap']['MAC owner']
                if host['nmap'].get('ports'):
                    buf += '\n PORTS:\t'
#                               print host['name'], host['nmap']['ports']
                    for i in host['nmap']['ports']:
                        #                         print host['name'],p
                        if len(i) >= 3:
                            buf += '\n    ' + i[0].decode("utf-8").ljust(9) + '\t' + i[2].decode("utf-8")
                else:
                    buf += '\n Host has no open ports!'
                if host['nmap'].get('Latency'):
                    buf += '\n Latency\t: ' + host['nmap']['Latency'].decode("utf-8")
        if host['state'].get('state') == 'down':
            buf += '\n Last seen\t: ' + time.ctime(host['state']['tst'])[4:-5]
        if host['state'].get('state') == 'up':
            buf += '\n Up since\t: ' + time.ctime(host['state']['tst'])[4:-5]
        return buf


if __name__ == '__main__':
    main()
