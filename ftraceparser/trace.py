from logging import StreamHandler
from os import write
import progressbar

from .tool_box import *
from .strings import *
from .node import Node
from .error import NodeTextError
from console import fg, bg, fx


class Trace:
    def __init__(self, as_servicve=False, logger=None, debug=False):
        self.trace_text = None
        self.n_cpu = 0
        self.n_task = 0
        self.node = []
        self.blacklist = []
        self.index2node = {}
        self.begin_node = {}
        self.filter_list = ['pid', 'cpu', 'task', 'time_stamp', 'event', 'entry']
        self.filter = {}
        self.logger = logger
        self.debug = debug
        self.as_servicve = as_servicve
        self.remove_filter_all()
        if self.logger == None:
           self.logger = init_logger(__name__, debug=self.debug, propagate=self.debug, handler_type=STREAM_HANDLER)
    
    def load_tracefile(self, trace_file):
        with open(trace_file, 'r') as f:
            self.trace_text = f.readlines()
        
    def load_trace(self, trace_text):
        if type(trace_text) == str:
            self.trace_text = trace_text.split('\n')
        else:
            self.trace_text = trace_text
    
    def convert_ftrace(self, ftrace_file, entry_functions: list, save_to=None):
        res = []
        waiting_buffer = {}
        context_switcher = '------------------------------------------'
        context_switch_regx = r'(\d+)\)( )+([\<\>\(\)a-zA-Z0-9\-\_\.]+)-(\d+)( )+=>( )+([\<\>\(\)a-zA-Z0-9\-\_\.]+)-(\d+)'
        content_regx = r'(\d+)\)((.+)(\|( )+)(([A-Za-z0-9_.]+\(\))(;| {)|}))'
        kernel_log_regx = r'\[(( )+)?(\d+\.\d+)\]\[(( )+)?T(\d+)\] (.+)'

        process = {}
        ftrace_fd = open(ftrace_file, 'r')
        texts = ftrace_fd.readlines()
        begin_cpu = {}
        for line in texts:
            line = line.strip()
            timestamp = regx_get(kernel_log_regx, line, 2)
            text = regx_get(kernel_log_regx, line, 6)
            if text == context_switcher:
                continue
            if regx_match(content_regx, text):
                cpu = regx_get(content_regx, text, 0)
                content = regx_get(content_regx, text, 1)
                cpu = int(cpu)
                if '}' in content:
                    event = 'funcgraph_exit'
                else:
                    event = 'funcgraph_entry'

                if cpu not in begin_cpu:
                    for entry in entry_functions:
                        if entry in content:
                            begin_cpu[cpu] = 1
                            break
                record = cpu in begin_cpu
                
                if record:
                    if cpu not in process:
                        res.append({'poc_name': None, 'pid': None, 'cpu': cpu, 'time_stamp': timestamp, 'event': event, 'info': content})
                    else:
                        res.append({'poc_name': process[cpu][0], 'pid': process[cpu][1], 'cpu': cpu, 'time_stamp': timestamp, 'event': event, 'info': content})
            
            if regx_match(context_switch_regx, text):
                cpu = regx_get(context_switch_regx, text, 0)
                cpu = int(cpu)
                poc_name_from = regx_get(context_switch_regx, text, 2)
                poc_pid_from = regx_get(context_switch_regx, text, 3)
                poc_name_to = regx_get(context_switch_regx, text, 6)
                poc_pid_to = regx_get(context_switch_regx, text, 7)
                if cpu not in process:
                    for each in res:
                        if each['cpu'] == cpu:
                            each['poc_name'] = poc_name_from
                            each['pid'] = poc_pid_from

                process[cpu] = [poc_name_to, poc_pid_to]
        
        if save_to == None:
            print("cpus={}".format(len(begin_cpu)))
            for each in res:
                print("{}-{}   [{}]   {}: {}: {}".format(each['poc_name'], each['pid'], each['cpu'], each['time_stamp'], each['event'], each['info']))
        else:
            with open(save_to, 'w') as f:
                f.write("cpus={}\n".format(len(begin_cpu)))
                for each in res:
                    f.write("{}-{}   [{}]   {}: {}: {}\n".format(each['poc_name'], each['pid'], each['cpu'], each['time_stamp'], each['event'], each['info']))
        return

    def serialize(self):
        node_id = 0
        abandoned_pid = []
        if self.trace_text == []:
            raise ValueError('Trace is empty')
        
        parents = {}
        self.begin_node = []
        self.trace_text[0]
        start = 0
        total_line = len(self.trace_text)

        for i in range(start, total_line):
            if regx_match(r'CPU (\d+) is empty', self.trace_text[i]):
                continue
            start = i
            break
        self.n_cpu = int(regx_get(r'cpus=(\d+)', self.trace_text[start], 0))
        last_node = Node(self.trace_text[start+1], node_id)
        self.node.append(last_node)
        self.index2node[node_id] = last_node
        parents[last_node.pid] = last_node
        self.begin_node.append(last_node)
        node_id += 1

        if last_node is None:
            raise ValueError('Trace is not valid')
        #bar = Bar('Processing', max=total_line)
        widgets=[
            ' [Serializing trace report] ',
            progressbar.Bar(),
            ' (', progressbar.Percentage(),' | ', progressbar.ETA(), ') ',
        ]

        if self.as_servicve:
            it = range(start+2, total_line)
        else:
            it = progressbar.progressbar(range(start+2, total_line), widgets=widgets)

        for i in it:
            line = self.trace_text[i].strip()

            try:
                child = Node(line, node_id)
            except NodeTextError:
                self.logger.error("Invalid node format {}".format(line))
                continue
            if child.pid in abandoned_pid:
                continue
            last_node.next_node_by_time = child
            child.prev_node_by_time = last_node
            last_node = child
            self.node.append(child)
            self.index2node[node_id] = last_node
            node_id += 1
            if child.pid in parents:
                try:
                    parents[child.pid].add_node(child)
                except Exception as e:
                    self.logger.error("pid {} missing node in trace, will be truncated".format(child.pid))
                    if child.pid not in abandoned_pid:
                        abandoned_pid.append(child.pid)
            else:
                self.begin_node.append(child)
            parents[child.pid] = child

        self.n_task = len(self.begin_node)
        return self.begin_node
    
    def show_filters(self):
        for filter_name in self.filter_list:
            if self.filter[filter_name] != None:
                self.logger.info('Filter: {}=={}'.format(filter_name, self.filter[filter_name]))
    
    def add_filter(self, filter_name, filter_expr):
        if filter_name in self.filter_list:
            self.filter[filter_name].append(filter_expr)
            return len(self.filter[filter_name]) - 1
    
    def remove_filter_all(self):
        for filter_name in self.filter_list:
            self.remove_filter(filter_name)

    def remove_filter(self, filter_name):
        if filter_name in self.filter_list:
            self.filter[filter_name] = []
    
    def remove_filter_inst(self, filter_name, index):
        if filter_name in self.filter_list:
            try:
                self.filter[filter_name].pop(index)
            except IndexError:
                self.logger.error('Index out of range')
    
    def is_filtered(self, node):
        for key in self.filter:
            for expr in self.filter[key]:
                if key == 'entry':
                    hop = self.get_hops_from_entry_node(node)
                    entry_node = self.find_node(hop.pop())
                    if not eval('\"{}\"{}'.format(getattr(entry_node, 'id'), expr)) \
                       and not eval('\"{}\"{}'.format(getattr(entry_node, 'function_name'), expr)):
                        return True
                elif key == 'pid' or key == 'cpu':
                    if not eval('{}{}'.format(getattr(node, key), expr)):
                        return True
                elif not eval('\"{}\"{}'.format(getattr(node, key), expr)):
                        return True
        return False
    
    def get_hops_from_entry_node(self, node):
        hop = [node.id]
        while node.parent != None:
            node = node.parent
            hop.append(node.id)
        return hop

    def find_node(self, node_id: int):
        if node_id in self.index2node:
                return self.index2node[node_id]
        return None
    
    def find_info(self, info, find_all=False, find_exact=False, start_node=None, end_node=None, in_func=False):
        res = []

        if start_node != None:
            bnode = self._next_node(start_node, in_func)
        else:
            bnode = self.begin_node[0]
        while bnode != None:
            if bnode.info.find(info) != -1:
                if not self.is_filtered(bnode):
                    if find_exact:
                        if bnode.info == (info + '() {'):
                            res.append(bnode)
                            if not find_all:
                                return res
                    else:
                        res.append(bnode)
                        if not find_all:
                            return res
            if bnode == end_node:
                break
            bnode = self._next_node(bnode, in_func)
        return res
    
    def print_banner(self):
        banner = "id{}|task{}| pid{} | cpu{}| time stamp: event".format((10-len('id'))*' ', (15-len('task'))*' ', (10-len('pid'))*' ', (7-len('cpu'))*' ')
        align = ' ' * (91 - len(banner))
        banner += align + '| info'
        print(banner)
    
    def print_cpu_banner(self):
        banner = '|'
        for i in range(self.n_cpu):
            banner += ' CPU {} |'.format(i)
        print(banner)
    
    def get_node(self, node, warn_when_filtered=False):
        if self.is_filtered(node):
            if warn_when_filtered:
                self.logger.warning('some nodes are filtered')
            return None
        return node
    
    def print_node(self, node, highlight=False, trim_bracket=False, warn_when_filtered=False):
        if node is None:
            print('Content has been truncated. This trace did not finish before killing the process.')
            return
        node = self.get_node(node, warn_when_filtered)
        if node is None:
            return
        data = node.text.split('|')
        align = 10 - len(str(node.id))
        if highlight:
            header = "{}{}|{}".format(fg.lightmagenta(str(node.id)), align*' ', fg.red(node.text))
        else:
            header = "{}{}|{}|{}|{}|{}{}".format(fg.lightmagenta(str(node.id)), align*' ', fg.yellow(data[0]), fg.yellow(data[1]), fg.cyan(data[2]), fg.green(data[3]), fg.yellow('|'+'|'.join((data[4:]))))
        if trim_bracket:
            header = header[:header.find('{')] + ';'
        print(header)
    
    def print_trace(self, start_node, level=0, length=30, end_node=None):
        if length <= 0 or start_node == None:
            return length
        if start_node.function_name in self.blacklist:
            return self.print_trace(start_node.next_sibling, level, length, end_node)
        self.print_node(start_node, trim_bracket=(level == 0 and start_node.children != []), warn_when_filtered=False)
        if end_node != None and start_node.id == end_node.id:
            return 0
        length -= 1
        if level != 0:
            if len(start_node.children) > 0:
                length = self.print_trace(start_node.children[0], level-1, length, end_node)

        if length != 0:
            if start_node.is_function and start_node.is_root and level>0:
                self.print_node(start_node.scope_end_node)
                length -= 1
                if end_node != None and start_node.scope_end_node.id == end_node.id:
                    return 0
        
        length = self.print_trace(start_node.next_sibling, level, length, end_node)
        return length
    
    def dump_to_json(self, file_name):
        with open(file_name, 'w') as f:
            widgets=[
                ' [Caching trace data] ',
                progressbar.Bar(),
                ' (', progressbar.Percentage(),' | ', progressbar.ETA(), ') ',
            ]
            for i in progressbar.progressbar(range(0, len(self.node)), widgets=widgets):
                each = self.node[i]
                f.writelines(json.dumps(each, default=self._dump_node_to_json, sort_keys=True, indent=4, check_circular=False)+'\n')
                f.write(boundary_regx+'\n')
            f.writelines(json.dumps(self, default=self._dump_trace_to_json, sort_keys=True, indent=4, check_circular=False)+'\n')
            f.close()
    
    def _next_node(self, node, in_func):
        if in_func:
            return node.next_node
        else:
            return node.next_node_by_time
    
    def _dump_node_to_json(self, o):
        if type(o.prev_node) == Node:
            o.prev_node = o.prev_node.id
        if type(o.next_node) == Node:
            o.next_node = o.next_node.id
        if type(o.prev_sibling) == Node:
            o.prev_sibling = o.prev_sibling.id
        if type(o.next_sibling) == Node:
            o.next_sibling = o.next_sibling.id
        if type(o.scope_begin_node) == Node:
            o.scope_begin_node = o.scope_begin_node.id
        if type(o.scope_end_node) == Node:
            o.scope_end_node = o.scope_end_node.id
        if type(o.parent) == Node:
            o.parent = o.parent.id
        if type(o.prev_node_by_time) == Node:
            o.prev_node_by_time = o.prev_node_by_time.id
        if type(o.next_node_by_time) == Node:
            o.next_node_by_time = o.next_node_by_time.id
        for i in range(0, len(o.children)):
            o.children[i] = o.children[i].id
        return o.__dict__
    
    def _dump_trace_to_json(self, o):
        for i in range(0, len(o.node)):
            o.node[i] = o.node[i].id
        for i in range(0, len(o.begin_node)):
            o.begin_node[i] = o.begin_node[i].id
        o.index2node = {}
        return o.__dict__
            