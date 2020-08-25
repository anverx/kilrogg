#!/usr/bin/env python
# Copyright (c) 2013, Anatoli Verkhovski
""" Eye of Kilrogg """

import gtk
import gtk.glade
import socket

import threading
import time
import gobject
import subprocess
import pickle
import os

import logging
import fcntl
import struct
import requests
try:
    from typing import Dict, Optional
except ImportError:
    Dict = dict
    Optional = None

import TreeViewTooltips
from filter import node_class_filter

SCAN_LOOP_DELAY = 30

IFACE = 'eth0'  # type: str
LOG = None  # type: Optional[logging.Logger]
host_list = {}
events = []
# ui = False

node_state_colors = {
    'recently down': '#FFe0e0',
    'recently up':   '#e0FFe0',
    'up':            '#F0FFF0',
    'down':          '#e0e0e0',
    'awhile down':   '#f0f0f0'
}


class NetThread(threading.Thread):
    """ All the network stuff is done in a separate thread so the gui wouldn't lock up """
    MACLOOKUPSITE = 'https://api.macvendors.com/'

    def __init__(self):
        threading.Thread.__init__(self)
        self.name = 'Net thread'
        self.daemon = True
        self.quit = False

    def run(self):
        LOG.debug('NetThread staring...')

        while True:
            # target = socket.gethostbyname(socket.gethostname())  # doesn't work everywhere
            tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            target = socket.inet_ntoa(fcntl.ioctl(tmp_sock.fileno(), 0x8915, struct.pack('256s', IFACE[:15]))[20:24])

            target = '.'.join(target.split('.')[:-1])  # s = string.join(s.split('.')[:-1],'.')
            target += '.0/24'
#                       s = 'fping -c1 -q -g '+s +'.0/24 2 >/dev/null'
#                       print 'command:', s
            fnull = open(os.devnull, 'w')
#            print 'fping', '-c1', '-q', '-g', target
            subprocess.call(['fping', '-c1', '-q', '-g', target], stderr=fnull)
            res = subprocess.check_output(['arp', '-n'])  # TODO change to reading of /proc/net/arp
            res = str(res).split('\n')

            fresh_host_list = {}
            for i in res:
                if i.rfind('(incomplete)') == -1:
                    row = i.split()
                    if len(row) > 2:
                        # print t, len(t), t[2],  t[2].find(':')

                        if row[2].find(':') != -1:
                            # LOG.debug('%s  %s', ','.join(row), i)
                            # tdata = dict(name = row[0], mac = row[2], iface = row[4], scan_tst = time.time() )
                            tdata = {'IP': row[0], 'mac': row[2],
                                     'iface': row[4], 'scan_tst': time.time()}  # type: Dict[str, str or float]
                            if True:  # not (host_list.get(row[2]) and  host_list[row[2]].get('IP')) :
                                try:
                                    # LOG.debug('looking up: %s', row[0] )
                                    tdata['name'] = socket.gethostbyaddr(row[0])[0]
                                except (socket.gaierror, socket.herror):  # as exc:
                                    tdata['name'] = tdata['IP']
                                    # LOG.debug(' lookup fails %s %s', row[0] ,str(exc))

                            for j in node_class_filter:
                                if tdata[j[0]].lower().startswith(j[1].lower()):
                                    tdata['node_class'] = j[2]
#                                                       node_class = ''
                            fresh_host_list[row[2]] = tdata
            LOG.debug('Found %d hosts', len(fresh_host_list))    
            self.update_host_list(fresh_host_list)
#            self.update_gui()

#                       for j in host_list:
#                               if not host_list[j].get('node_class'):
#                                       print j, host_list[j]
#                                       model.append((host_list[j]['name'],''))

            time.sleep(SCAN_LOOP_DELAY)
            if self.quit:
                return

    @staticmethod
    def nmap(host):
        """
        :param str host:
        :return:
        """
        res = {'state': 'up', 'tst': time.time()}
        LOG.debug('nmaping host: %s ...', host)
        nmap = subprocess.check_output(['nmap', '-Pn', host])
        if 'Host is down' in nmap:
            res['state'] = 'down'
            return res
        # if nmap[2].find('down') != -1:
        #    res['state'] = 'down'
        #    return res
        # res['state'] = 'up'
        try:
            res['IP'] = nmap[2].strip().split(' ')[-1]
            res['Latency'] = nmap[3].strip().split(' ')[-2][1:]
        except IndexError:
            logging.warning('nmap index error: res: %r', nmap, exc_info=True)

        if nmap[4].find('All 1000') == -1:  # if have open ports
            res['ports'] = []
            for i in nmap[6:]:
                if i[:12] == 'MAC Address:':
                    res['MAC'] = i.strip().split()[2]
                    res['MAC owner'] = i[i.find('('):]
                    break
                if not i:  # when ran as user namp won't give MAC or MAC owner
                    break
                res['ports'].append(i.split())

        LOG.debug('Nmap %s : %s', host, str(res))
        return res

    def mac_manufacturer(self, mac):
        """

        :param str mac:
        :return:
        :rtype: Optional[str]
        """

        try:
            r = requests.get(self.MACLOOKUPSITE + mac)
            # LOG.debug('reply: %s errors: %r not found %r', r, 'errors' in r, 'Not Found')
            if 'errors' in r.text:

                if 'Not Found' in r.text:    # If not found return Not Found
                    LOG.debug('mac %s not found', mac)
                    return 'Not Found'
                LOG.debug('Errors: %s', r)  # if any other error return None
                return None
            return r.text
        except requests.exceptions.ConnectionError as exc:
            LOG.debug('Connection to % failed: %s', self.MACLOOKUPSITE, exc)
        return None

        # pass

    def update_host_list(self, new_list):
        do_nmap = True

        for i in host_list:
            if not host_list[i].get('state'):  # if state is missing from record
                host_list[i]['state'] = {'state': 'down', 'tst': 0, 'color': '#A0A0A0'}
            if new_list.get(i):
                if host_list[i]['state']['state'] == 'down':
                    host_list[i]['state'] = {'state': 'up', 'tst': time.time()}
                    events.append({'host_name': host_list[i]['name'],
                                   'host_mac': host_list[i]['mac'], 'event': 'host up', 'tst': time.time()})
            
            else:  # if host is present in old list but absent in new list
                if True:  # time.time() - host_list[i]['scan_tst'] < SCAN_LOOP_DELAY * 1.5:
                    # #TODO report once and exactly once
                    if host_list[i].get('state') and host_list[i]['state'].get('state') != 'down':
                        events.append({'host_name': host_list[i]['name'], 'host_mac': host_list[i]['mac'],
                                       'event': 'host down', 'tst': time.time()})
                        
                    host_list[i]['state'] = {'state': 'down', 'tst': host_list[i]['scan_tst']}

        for i in new_list:
            if host_list.get(i):
                if host_list[i].get('name') != new_list[i].get('name'):
                    LOG.debug('Host changed name: %s %s', host_list[i].get('name'), new_list[i].get('name'))
                if host_list[i].get('IP') != new_list[i].get('IP'):
                    LOG.debug('Host changed IP: %s %s', host_list[i].get('IP'), new_list[i].get('IP'))
                                
                host_list[i].update(new_list[i])
                if not host_list[i].get('names'):
                    host_list[i]['names'] = []
                    
                if not host_list[i].get('IPs'):
                    host_list[i]['IPs'] = []
                
                # host can have multiple names and IPs over period of time, remember them all
                if new_list[i].get('name') not in host_list[i]['names']:  
                    host_list[i]['names'].append(new_list[i]['name'])
               
                if new_list[i].get('IP') not in host_list[i]['IPs']:
                    host_list[i]['IPs'].append(new_list[i]['IP'])
            else:
                host_list[i] = new_list[i]
                host_list[i]['state'] = {'state': 'up', 'tst': time.time()}
                events.append({'host_name': new_list[i]['name'], 'host_mac': new_list[i]['mac'],
                               'event': 'new host', 'tst': time.time()})
#                               print {'host_name' : new_list[i]['name'],
#                                       'host_mac' : new_list[i]['mac'],
#                                       'event' : 'new host'}

            if do_nmap:
                # LOG.debug('Host: %s  nmap: %s', host_list[i]['name'], str(host_list[i].get('nmap')))
                if not host_list[i].get('nmap') or time.time()-host_list[i]['nmap']['tst'] > 60*60*24:  # daily nmap
                    host_list[i]['nmap'] = self.nmap(host_list[i]['name'])

#                               if host_list[i].get('nmap') and
#                                       host_list[i]['nmap']['state'] == 'down' and
#                                       time.time()-host_list[i]['scan_tst'] < SCAN_LOOP_DELAY *2:
#                                       host_list[i]['nmap'] = self.nmap(host_list[i]['name'])
                    do_nmap = False
        
            if not host_list[i].get('mac owner') or 'errors' in host_list[i].get('mac owner'):
                # LOG.debug('o: %s', host_list[i]['mac owner'])
                host_list[i]['mac owner'] = self.mac_manufacturer(i)
                LOG.debug(' MAC: %s owner: %s', i, host_list[i]['mac owner'])
                time.sleep(2)

        for i in host_list:
            if host_list[i]['state']['state'] == 'down':
                # LOG.debug('Host %s down: %d min', host_list[i]['name'],
                #         int(time.time()-host_list[i]['state']['tst'])/60)
                if time.time()-host_list[i]['state']['tst'] < 60*5:
                    host_list[i]['state']['color'] = node_state_colors['recently down']
                elif time.time()-host_list[i]['state']['tst'] < 60*60*5:
                    host_list[i]['state']['color'] = node_state_colors['down']
                else:
                    host_list[i]['state']['color'] = node_state_colors['awhile down']
            else:
                if time.time()-host_list[i]['state']['tst'] < 60*5:
                    host_list[i]['state']['color'] = node_state_colors['recently up']
                else:
                    host_list[i]['state']['color'] = node_state_colors['up']


class MyTooltips(TreeViewTooltips.TreeViewTooltips):
    def get_tooltip(self, view, column, path):
        """ Overloading the method to fetch tooltip data from treeview model, column 4 """
        
        buf = view.get_model()[path[0]][4]
        return buf


def main():
    """ Main thread is the gui thread, in addition a networking thread is started, it scans the net for  """
    global host_list, events, LOG

    logging.basicConfig()
    LOG = logging.getLogger('kilrogg')
    LOG.setLevel(logging.DEBUG)
    LOG.debug('starting...')   
    gobject.threads_init()
    
#    host_list = ()
#    events = {}
    if os.path.isfile("kilrogg.p"):
        try:
            tmp = pickle.load(open("kilrogg.p", "rb"))
            host_list = tmp.get('hosts', {})
            events = tmp.get('events', [])
        except (IOError, AttributeError) as exc:
            LOG.warning('REading pickled data: %s', exc)
            pass
    
    _ = GUI()
    
    netthread = NetThread()
#    netthread.update_gui()
    netthread.start()
    LOG.debug('starting gtk.main')
    try:
        gtk.main()
        netthread.quit = True
        time.sleep(1)  # wait for nethread to terminate        
    
    finally:
        pickle.dump({'hosts': host_list, 'events': events},  open("kilrogg.p", "wb"))


class GUI(object):
    GLADE_FILE = './kilrogg.glade'

    def __init__(self):
        self.gui = gtk.glade.XML(self.GLADE_FILE)
        self.gui.get_widget('window1').connect("destroy", gtk.main_quit)
        self.gui.get_widget('window1').show_all()
    
        tview = self.gui.get_widget('Hosts')
        # Host type fg color, bg color, tooltip, mac
        tview.set_model(gtk.ListStore(str, str, str, str, str, str))
        tview.append_column(gtk.TreeViewColumn('Host', gtk.CellRendererText(), text=0, background=3))

        tview.append_column(gtk.TreeViewColumn('type', gtk.CellRendererText(), text=1, background=3))
    
        #    ui.treeview_debug.append_column(gtk.TreeViewColumn('Value', gtk.CellRendererText(), text=1))
        #    ui.treeview_debug.append_column(gtk.TreeViewColumn('Type',  gtk.CellRendererText(), text=2))
        for i in tview.get_columns():
            i.set_sizing(gtk.TREE_VIEW_COLUMN_AUTOSIZE)
        # tv.get_model().append(('Gagaga',))
        # tv.get_model().append(('HaHaHa',))
        mytips = MyTooltips()
        mytips.add_view(tview)
    
        tview.connect("button-press-event", self.on_treeview_button_press_event)

        tve = self.gui.get_widget('Events')
        tve.set_model(gtk.ListStore(str, str))
        tve.append_column(gtk.TreeViewColumn('Time',  gtk.CellRendererText(), text=0))
        tve.append_column(gtk.TreeViewColumn('Event', gtk.CellRendererText(), text=1))
        for i in tve.get_columns():
            i.set_sizing(gtk.TREE_VIEW_COLUMN_AUTOSIZE)
        
#        for i in reversed(events):
#           tve.get_model().append((i.get('tst'), i.get('event') or '' +' '+i['host_name']))
            
        self.update_gui()
        gobject.timeout_add(2000, self.update_gui)  # install repaint timer
        
    @staticmethod
    def on_external(_, params):
        if params['command'] == 'ssh':
            os.system('xterm -e ssh ' + params['target'] + ' -l root &')
        if params['command'] == 'http':
            LOG.debug('http://' + params['target'])
            subprocess.Popen(['xdg-open', 'http://' + params['target']])

    def on_label(self, _, host):
        """ Label a host """
        self.gui.get_widget('label_head1').set_markup('<b>Set custom label for host %s</b>'
                                                      % host_list[host]['name'])
        try: 
            res = self.gui.get_widget('dialog_label').run()
            if res == gtk.RESPONSE_OK:
                LOG.debug('OK: label:%s, host: %s', self.gui.get_widget('entry_label').get_text(), str(host_list[host]))
                host_list[host]['label'] = self.gui.get_widget('entry_label').get_text()
        finally:
            self.gui.get_widget('dialog_label').hide()
    
    def on_treeview_button_press_event(self, treeview, event):
        if event.button == 3:
            x = int(event.x)
            y = int(event.y)
            etime = event.time
            pthinfo = treeview.get_path_at_pos(x, y)
            if pthinfo is not None:
                path, col, cellx, celly = pthinfo
                treeview.grab_focus()
                treeview.set_cursor(path, col, 0)
                hosts_popup = gtk.Menu()
                
                host = host_list[treeview.get_model()[path[0]][5]]
                mitem = gtk.MenuItem('Label ... ')
                hosts_popup.append(mitem)
                mitem.connect("activate", self.on_label, host['mac'])
                mitem.show()

                if host.get('nmap') and host['nmap'].get('ports'):
                    for i in host['nmap']['ports']:
                        if i[2] == 'ssh':
                            mi = gtk.MenuItem('ssh as root')
                            hosts_popup.append(mi)
                            mi.connect("activate", self.on_external, {'target': host['name'], 'command': 'ssh'})
                            mi.show()
                        if i[2] == 'http':
                            mi = gtk.MenuItem('http')
                            hosts_popup.append(mi)
                            mi.connect("activate", self.on_external, {'target': host['name'], 'command': 'http'})
                            mi.show()
    
                hosts_popup.popup(None, None, None, event.button, etime)
            return True

    def update_gui(self):
        """ Repaint GUI """
#        LOG.debug('update gui')
        model = self.gui.get_widget('Hosts').get_model()
#        tmp = host_list.values()
        sorted_list = sorted(host_list.values(), key=lambda k: k['name'])

        class_list = []
        other_list = []
        old_list = []

        for j in sorted_list:  # sort host list into groups
            if j['scan_tst'] < time.time() - 60*60*24*7:
                old_list.append(j)
                continue
            if j.get('node_class'):
                class_list.append(j)
                continue
            other_list.append(j)               

        model.clear()                
        for group_list in (sorted(class_list, key=lambda k: k['node_class']), other_list, old_list):
            for j in group_list:
                color = '#e0e0e0'
                if j.get('state') and j['state'].get('color'):
                    color = j['state']['color']
                buf = self.format_tooltip(j)
                column2 = ''
                if j.get('label'):
                    column2 = j['label']+' '
                if j.get('node_class'):
                    column2 += '('+j.get('node_class')+')'
                if j.get('mac owner') and 'Not Found' not in j.get('mac owner'):
                    column2 += '['+j.get('mac owner')+']'
#                LOG.debug('label: %s class: %s  column2: %s', j.get('label'),j.get('node class'))
                model.append((j['name'], column2, '#88FF88', color, buf, j['mac']))

        tve = self.gui.get_widget('Events')
        tve.get_model().clear()
        
        count = 0  # limit number of events shown to 200
        for i in reversed(events):
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
                    buf += '\n IP   \t\t: '+host['nmap']['IP']
                if host['nmap'].get('MAC owner'):
                    buf += '\n MAC owner\t:'+host['nmap']['MAC owner']
                if host['nmap'].get('ports'):
                    buf += '\n PORTS:\t'
#                               print host['name'], host['nmap']['ports']
                    for i in host['nmap']['ports']:
                        #                         print host['name'],p
                        if len(i) < 3:
                            pass
#                           print 'Grabage in port list, host:',host['name'],p
                        else:
                            buf += '\n    ' + i[0].ljust(9) + '\t' + i[2]
                else:
                    buf += '\n Host has no open ports!'
                if host['nmap'].get('Latency'):
                    buf += '\n Latency\t: ' + host['nmap']['Latency']
        if host['state'].get('state') == 'down':
            buf += '\n Last seen\t: ' + time.ctime(host['state']['tst'])[4:-5]
        if host['state'].get('state') == 'up':
            buf += '\n Up since\t: ' + time.ctime(host['state']['tst'])[4:-5]
        return buf


if __name__ == '__main__':
    main()
