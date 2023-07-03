#!/bin/env python

import os
import logging
import threading
import time
import socket
import fcntl
import subprocess
import struct
import pickle
import requests
from filter import node_class_filter
from typing import List, Dict


class NetScanner(threading.Thread):
    """ All the network stuff is done in a separate thread so the gui wouldn't lock up """
    MAC_LOOKUP_SITE = 'https://api.macvendors.com/'
    MANUFACTURER_DB = 'manufacturer_db.p'
    HOST_DB = 'kilrogg.p'
    COLUMN_MAC = 3
    COLUMN_IP = 0
    COLUMN_INTERFACE = 5
    SCAN_LOOP_DELAY = 30

    def __init__(self):
        threading.Thread.__init__(self)
        self.name = 'Net thread'
        self.daemon = True
        self.quit = False
        self.manufacturer_db = {}
        self.host_list = {}
        self.events = []  # type: List[Dict[str, str]]

        self.load()

    def load(self):
        """
        Load the 3 databases from pickles
        """
        if os.path.isfile(self.HOST_DB):
            try:
                tmp = pickle.load(open(self.HOST_DB, 'rb'))
                self.host_list = tmp.get('hosts', {})
                logging.info('Loaded %d hosts.', len(self.host_list))
                self.events = tmp.get('events', [])
                logging.info('Loaded %d events.', len(self.events))
            except (IOError, AttributeError) as exc:
                logging.warning('Reading pickled data: %s', exc)

        if os.path.isfile(self.MANUFACTURER_DB):
            try:
                self.manufacturer_db = pickle.load(open(self.MANUFACTURER_DB, 'rb'))
                logging.info('Loaded manufacturers for %d hosts.', len(self.manufacturer_db))
            except (IOError, AttributeError) as exc:
                logging.warning('Reading pickled data: %s', exc)

    def save(self):
        """
        Save hosts and events databases
        """
        pickle.dump({'hosts': self.host_list, 'events': self.events}, open(self.HOST_DB, "wb"))

    @staticmethod
    def get_default_iface_name_linux():
        """
        straight from
        stackoverflow.com/questions/20908287/is-there-a-method-to-get-default-network-interface-on-local-using-python3
        """
        route = "/proc/net/route"
        with open(route) as f:
            for line in f:
                try:
                    iface, dest, _, flags, _, _, _, _, _, _, _, = line.strip().split()
                    if dest != '00000000' or not int(flags, 16) & 2:
                        continue
                    return iface
                except (AttributeError, TypeError, ValueError):
                    continue
        return None

    def run(self):
        logging.debug('NetThread staring...')

        while True:
            iface = self.get_default_iface_name_linux()
            if not iface:
                logging.debug('Couldn\'t nefault network interface')
                time.sleep(5)
                continue
            # target = socket.gethostbyname(socket.gethostname())  # doesn't work everywhere
            try:
                tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # target = socket.inet_ntoa(fcntl.ioctl(tmp_sock.fileno(),
                # 0x8915, struct.pack('256s', IFACE[:15]))[20:24])
                target = socket.inet_ntoa(fcntl.ioctl(tmp_sock.fileno(), 0x8915,
                                                      struct.pack('256s', iface.encode()))[20:24])
            except IOError as exc:
                logging.debug('Couldn\'t get local IP: %s', exc)
                time.sleep(5)
                continue

            target = '.'.join(target.split('.')[:-1]) + '.0/24'
            #                       s = 'fping -c1 -q -g '+s +'.0/24 2 >/dev/null'
            #                       print 'command:', s
            fnull = open(os.devnull, 'w')
            #            print 'fping', '-c1', '-q', '-g', target
            subprocess.call(['fping', '-c1', '-q', '-g', target], stderr=fnull)
            # res = subprocess.check_output(['arp', '-n'])  # TODO change to reading of /proc/net/arp
            res = open('/proc/net/arp').read()
            res = str(res).split('\n')

            fresh_host_list = {}
            for i in res:
                if i.rfind('(incomplete)') == -1:
                    row = i.split()
                    # print ('row: ', row)
                    if len(row) > 2:
                        # print t, len(t), t[2],  t[2].find(':')

                        if row[self.COLUMN_MAC].find(':') != -1:
                            # LOG.debug('%s  %s', ','.join(row), i)
                            # tdata = dict(name = row[0], mac = row[2], iface = row[4], scan_tst = time.time() )
                            tdata = {'IP': row[self.COLUMN_IP], 'mac': row[self.COLUMN_MAC],
                                     'iface': row[self.COLUMN_INTERFACE],
                                     'scan_tst': time.time()}  # type: Dict[str, str|float]
                            if True:  # not (host_list.get(row[2]) and  host_list[row[2]].get('IP')) :
                                try:
                                    # LOG.debug('looking up: %s', row[0] )
                                    tdata['name'] = socket.gethostbyaddr(row[self.COLUMN_IP])[0]
                                except (socket.gaierror, socket.herror):  # as exc:
                                    tdata['name'] = tdata['IP']
                                    # LOG.debug(' lookup fails %s %s', row[0] ,str(exc))

                            for j in node_class_filter:
                                if tdata[j[0]].lower().startswith(j[1].lower()):
                                    tdata['node_class'] = j[2]
                            #                                                       node_class = ''
                            fresh_host_list[row[self.COLUMN_MAC]] = tdata
                            # print(repr(tdata))
            logging.debug('Found %d hosts', len(fresh_host_list))
            self.update_host_list(fresh_host_list)
            #            self.update_gui()

            #                       for j in host_list:
            #                               if not host_list[j].get('node_class'):
            #                                       print j, host_list[j]
            #                                       model.append((host_list[j]['name'],''))

            time.sleep(self.SCAN_LOOP_DELAY)
            if self.quit:
                return

    @staticmethod
    def nmap(host):
        """
        :param str host:
        :return:
        """
        res = {'state': 'up', 'tst': time.time()}
        logging.debug('nmaping host: %s ...', host)
        nmap = subprocess.check_output(['nmap', '-Pn', host])
        if b'Host is down' in nmap:
            res['state'] = 'down'
            return res
        # if nmap[2].find('down') != -1:
        #    res['state'] = 'down'
        #    return res
        # res['state'] = 'up'
        nmap = nmap.strip().split(b'\n')
        for i in range(4):
            logging.debug('    %d  [%s]', i, nmap[i])
        try:
            res['IP'] = nmap[1].strip().split(b' ')[-1]
            res['Latency'] = nmap[2].strip().split(b' ')[-2][1:]
        except IndexError:
            logging.warning('nmap index error: res: %r', nmap, exc_info=True)

        if nmap[4].find(b'All 1000') == -1:  # if have open ports
            res['ports'] = []
            for i in nmap[5:]:
                if i[:12] == 'MAC Address:':
                    res['MAC'] = i.strip().split()[2]
                    res['MAC owner'] = i[i.find(b'('):]
                    break
                if not i:  # when ran as user namp won't give MAC or MAC owner
                    break
                res['ports'].append(i.split())

        # LOG.debug('Nmap %s : %s', host, str(res))
        return res

    def mac_manufacturer(self, mac):
        """

        :param str mac:
        :return:
        :rtype: str|None
        """
        if mac in self.manufacturer_db:
            return self.manufacturer_db[mac]

        try:
            logging.debug('Mac: %s [%s]', mac, repr(mac))
            r = requests.get(self.MAC_LOOKUP_SITE + mac)
            # LOG.debug('reply: %s errors: %r not found %r', r, 'errors' in r, 'Not Found')
            if 'errors' in r.text:
                if 'Not Found' in r.text:  # If not found return Not Found
                    logging.debug('mac %s not found', mac)
                    return 'Not Found'
                logging.debug('Errors: %s', r)  # if any other error return None
                return None
            self.manufacturer_db[mac] = r.text
            pickle.dump(self.manufacturer_db, open(self.MANUFACTURER_DB, 'wb'))
            return r.text
        except requests.exceptions.ConnectionError as exc:
            logging.debug('Connection to % failed: %s', self.MAC_LOOKUP_SITE, exc)
        return None

        # pass

    def update_host_list(self, new_list):
        do_nmap = True

        for i in self.host_list:
            if not self.host_list[i].get('state'):  # if state is missing from record
                self.host_list[i]['state'] = {'state': 'down', 'tst': 0, 'color': '#A0A0A0'}
            if new_list.get(i):
                if self.host_list[i]['state']['state'] == 'down':
                    self.host_list[i]['state'] = {'state': 'up', 'tst': time.time()}
                    self.events.append({'host_name': self.host_list[i]['name'],
                                   'host_mac': self.host_list[i]['mac'], 'event': 'host up', 'tst': time.time()})

            else:  # if host is present in old list but absent in new list
                if True:  # time.time() - host_list[i]['scan_tst'] < SCAN_LOOP_DELAY * 1.5:
                    # #TODO report once and exactly once
                    if self.host_list[i].get('state') and self.host_list[i]['state'].get('state') != 'down':
                        self.events.append({'host_name': self.host_list[i]['name'], 'host_mac': self.host_list[i]['mac'],
                                       'event': 'host down', 'tst': time.time()})

                    self.host_list[i]['state'] = {'state': 'down', 'tst': self.host_list[i]['scan_tst']}

        # logging.debug('New list: %s', repr(new_list))
        for i in new_list:
            if self.host_list.get(i):
                if self.host_list[i].get('name') != new_list[i].get('name'):
                    logging.debug('Host changed name: %s %s', self.host_list[i].get('name'), new_list[i].get('name'))
                if self.host_list[i].get('IP') != new_list[i].get('IP'):
                    logging.debug('Host changed IP: %s %s', self.host_list[i].get('IP'), new_list[i].get('IP'))

                self.host_list[i].update(new_list[i])
                if not self.host_list[i].get('names'):
                    self.host_list[i]['names'] = []

                if not self.host_list[i].get('IPs'):
                    self.host_list[i]['IPs'] = []

                # host can have multiple names and IPs over period of time, remember them all
                if new_list[i].get('name') not in self.host_list[i]['names']:
                    self.host_list[i]['names'].append(new_list[i]['name'])

                if new_list[i].get('IP') not in self.host_list[i]['IPs']:
                    self.host_list[i]['IPs'].append(new_list[i]['IP'])
            else:
                self.host_list[i] = new_list[i]
                self.host_list[i]['state'] = {'state': 'up', 'tst': time.time()}
                self.events.append({'host_name': new_list[i]['name'], 'host_mac': new_list[i]['mac'],
                               'event': 'new host', 'tst': time.time()})
            #                               print {'host_name' : new_list[i]['name'],
            #                                       'host_mac' : new_list[i]['mac'],
            #                                       'event' : 'new host'}

            if do_nmap:
                # LOG.debug('Host: %s  nmap: %s', host_list[i]['name'], str(host_list[i].get('nmap')))
                try:
                    if not self.host_list[i].get('nmap') or time.time() - self.host_list[i]['nmap'][
                        'tst'] > 60 * 60 * 24:  # daily nmap
                        logging.debug('Nmapping %s', self.host_list[i]['name'])
                        self.host_list[i]['nmap'] = self.nmap(self.host_list[i]['name'])

                    #                               if host_list[i].get('nmap') and
                    #                                       host_list[i]['nmap']['state'] == 'down' and
                    #                                       time.time()-host_list[i]['scan_tst'] < SCAN_LOOP_DELAY *2:
                    #                                       host_list[i]['nmap'] = self.nmap(host_list[i]['name'])
                    do_nmap = False
                except IndexError:
                    logging.info('%r', self.host_list[i])

            if not self.host_list[i].get('mac owner') or 'errors' in self.host_list[i].get('mac owner'):
                # LOG.debug('o: %s', host_list[i]['mac owner'])
                # print( 'Looking up mac: ', repr(i))
                self.host_list[i]['mac owner'] = self.mac_manufacturer(i)
                logging.debug(' MAC: %s owner: %s', i, self.host_list[i]['mac owner'])
                time.sleep(2)

def main():
    logging.basicConfig(format='%(asctime)s - %(levelname)s %(filename)s(%(lineno)s):%(funcName)s %(message)s',
                        level=logging.DEBUG)
    # LOG = logging.getLogger('kilrogg')
    logging.getLogger().setLevel(logging.DEBUG)
    logging.debug('Starting...')
    nt = NetScanner()
    nt.start()
    nt.join()

if __name__ == '__main__':
    main()
