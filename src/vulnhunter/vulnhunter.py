import ida_idaapi # type: ignore # 框架的核心定义
import ida_kernwin # type: ignore # 和IDA界面交互的功能，例如打印消息
import ida_hexrays # type: ignore
import ida_funcs # type: ignore
import idc # type: ignore
import ida_moves # type:ignore
import idaapi # type:ignore
import ida_xref # type:ignore
import threading
import idautils # type:ignore
from ida_kernwin import Choose # type:ignore
import ida_nalt # type:ignore
import re

# -------------------------------------------------------------
#                     全局变量部分
# -------------------------------------------------------------

START_ADDR = -1
TARGET_ADDR = -1
ALL_PATH = []
PATH_INDEX = 0
PATH_COLOR_INDEX = 0
MCP_PORT = 9673
DANGER_ADDR = -1


MARKED_LINES = {}            # 控制伪代码某行的颜色
COLORS = {                   # 颜色列表
    'blue': ida_kernwin.CK_EXTRA6,
    'green': ida_kernwin.CK_EXTRA7,
    'red': ida_kernwin.CK_EXTRA11,
    'orange': ida_kernwin.CK_EXTRA3,
    'golden': ida_kernwin.CK_EXTRA2,
    'pink': ida_kernwin.CK_EXTRA4,
    'orange_yellow': ida_kernwin.CK_EXTRA5,
    'grey': ida_kernwin.CK_EXTRA8,
    'pink2': ida_kernwin.CK_EXTRA9,
    'yellow': ida_kernwin.CK_EXTRA12
}

# -------------------------------------------------------------
#                     IDA 插件主程序部分
# -------------------------------------------------------------

# 注册插件，需要继承于ida_idaapi.plugin_t
class VulnHunter(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP      # 定义插件的生命周期，设置为PLUGIN_UNL会让调用插件后立即卸载，PLUGIN_KEEP可以让其一直保存在内存中，等等
    comment = "Find paths from start to destination"          # 插件的描述
    wanted_name = "VulnHunter"          # 在edit-plugins中显示的名称
    wanted_hotkey = "Shift-V"           # 快捷键，例如我们这里使用Shift-v
    help = ""
    
    def init(self):        
        # 注册动作
        self.actions = [
            ida_kernwin.action_desc_t(
                name='vulnHunter::SetStartAddr',
                label='CallChain: set as start address',
                handler=SetStartAddrAction(),
                shortcut=None,
                tooltip='Set the start address of VulnHunter',
                icon=139
            ),
            ida_kernwin.action_desc_t(
                name='vulnHunter::SetDestAddr',
                label='CallChain: set as target address',
                handler=SetDestAddrAction(),
                shortcut=None,
                tooltip='Set the point address of VulnHunter',
                icon=139
            ),
            ida_kernwin.action_desc_t(
                name='vulnHunter::Hunt',
                label='CallChain: start to find call chains',
                handler=HuntAction(),
                shortcut='Shift-V',
                tooltip='Begin find paths from start to destination address',
                icon=139
            ),
            ida_kernwin.action_desc_t(
                name='vulnHunter::Index',
                label='VulnHunt Next Index',
                handler=NextPathAction(),
                shortcut='Shift-i',
                tooltip='next path',
                icon=139
            ),
            ida_kernwin.action_desc_t(
                name='vulnHunter::Test',
                label='VulnHunt Test',
                handler=TestAction(),
                shortcut='Shift-T',
                tooltip='Test',
                icon=139
            ),
            ida_kernwin.action_desc_t(
                name='vulnHunter::ConstantXrefs',
                label='Xrefs: find xrefs with constant value params',
                handler=ConstantXrefsAction(),
                shortcut='Ctrl+x',
                tooltip='find xrefs with constant value params',
                icon=139
            ),
            ida_kernwin.action_desc_t(
                name='vulnHunter::ContextXrefs',
                label='Xrefs: find context xrefs',
                handler=ContextXrefsAction(),
                shortcut='',
                tooltip='set danger function for context xrefs',
                icon=139
            ),
            ida_kernwin.action_desc_t(
                name='vulnHunter::SetDangerFunction',
                label='Xrefs: set danger function',
                handler=SetContextXrefsAction(),
                shortcut='',
                tooltip='set danger function for context xrefs',
                icon=139
            ),

            # SetContextXrefsAction
        ]
        
        for action in self.actions:
            if not ida_kernwin.register_action(action):
                ida_kernwin.msg(f"VulnHunter: plugin function {action.action_name} register failed.\n")
        
        # 实例化并安装UI的钩子
        self.ui_hooks = {RightMouseHook(), pseudocode_lines_rendering_hooks_t()}
        
        for hook in self.ui_hooks:
            if not hook.hook(): # 安装钩子
                ida_kernwin.msg("VulnHunter: The UI Hook install failed. Please check your script.\n")
        
        # 开启端口供MCP使用
        mcp_thread = threading.Thread(target=open_port_for_mcp) 
        mcp_thread.daemon = True # 设置为守护线程
        mcp_thread.start()

        return ida_idaapi.PLUGIN_KEEP

# 执行器
class VulnHunter_Runner(ida_idaapi.plugmod_t):
    # 用户触发插件时，会触发该功能
    def run(self, arg):
        ida_kernwin.msg("VulnHunter: Exec Func\n")
        
# -------------------------------------------------------------
#                     自定义对象
# -------------------------------------------------------------

# 表示某个函数的第某行
class pseudo_line_t(object):
    def __init__(self, func_ea, linr_nr):
        self.func_ea = func_ea
        self.linr_nr = linr_nr
        
    def __hash__(self):
        return hash((self.func_ea, self.linr_nr))

    def __eq__(self, r):
        return self.func_ea == r.func_ea  and self.linr_nr == r.linr_nr

# 地址对，表示call指令所在的地址和函数地址的起始地址
# 例如：0x1210 call printf这个对象为(0x1210，addr_of_printf)
class CallChainLink(object):
    def __init__(self, call_ea, func_ea):
        self.call_ea = call_ea
        self.func_ea = func_ea
    
    def __hash__(self):
        return hash((self.call_ea, self.func_ea))

    def __eq__(self, other):
        return self.call_ea == other.call_ea and self.func_ea == other.func_ea
    
    def __str__(self):
        return f"(call_ea:{self.call_ea}, func_ea:{self.func_ea})"
    
    def __repr__(self):
        # 返回一个你希望看到的、具有可读性的字符串
        return f"<CallChainLink call: 0x{self.call_ea:x} -> func: 0x{self.func_ea:x}>"

# -------------------------------------------------------------
#                     自定义函数 - 高亮控制
# -------------------------------------------------------------

# 接收一个place_t对象，将其转换为simpleline_place_t，随后取n获取其行号
def _place_to_line_number(p):
    return ida_kernwin.place_t.as_simpleline_place_t(p).n

# 接收一个ea，获得行号
# 大力出奇迹，采用跳转过去的方式来获取行号（因为没找到api鸭，感觉都是基于ctx或者place_t的）
def _ea_to_line_number(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        ida_kernwin.msg(f"VulnHunter: _ea_to_line_number failed: The address 0x{ea:x} is not a valid address.\n")
        return -1
    original_ea = ida_kernwin.get_screen_ea() # 保存当前地址
    
    ida_kernwin.jumpto(ea) # 直接就是跳转
    widget = ida_kernwin.get_current_widget()
    vdui = ida_hexrays.get_widget_vdui(widget)
    
    lnnum = vdui.cpos.lnnum
    if not vdui:
        ida_kernwin.info(f"VulnHunter: failed to get vdui.\n")
        ida_kernwin.jumpto(original_ea)
        return -1
    
    ida_kernwin.jumpto(original_ea)
    return lnnum


def set_color_by_ea(ea, color):
    global MARKED_LINES
    lnnum = _ea_to_line_number(ea)
    func_addr = ida_funcs.get_func(ea).start_ea
    # ida_kernwin.msg(f"func_addr: 0x{func_addr:x}, lnnum:{lnnum}.\n")
    coord = pseudo_line_t(func_addr, lnnum)
    if coord in MARKED_LINES.keys():
        del MARKED_LINES[coord]
    else:
        MARKED_LINES[coord] = color
    ida_kernwin.refresh_custom_viewer(ida_kernwin.get_current_widget()) # 手动刷新伪代码窗口，触发UI Hook
        
def clear_color():
    global MARKED_LINES
    MARKED_LINES = {}
    ida_kernwin.refresh_custom_viewer(ida_kernwin.get_current_widget())

# 接收一个ctx，设置该行在伪代码的颜色
def set_color_by_ctx(ctx, color):
    global MARKED_LINES
    # COLOR_KEYY = ida_kernwin.CK_EXTRA11
    vu = ida_hexrays.get_widget_vdui(ctx.widget) # 只有伪代码会返回vdui_t，不然返回None
    if vu:
        loc = ida_moves.lochist_entry_t()
        if ida_kernwin.get_custom_viewer_location(loc, ctx.widget):
            coord = pseudo_line_t(vu.cfunc.entry_ea, _place_to_line_number(loc.place()))
            
            # 如果已经设置了颜色，则清除颜色
            
            if coord in MARKED_LINES.keys():
                del MARKED_LINES[coord]
            else:
                MARKED_LINES[coord] = color
            
            ida_kernwin.refresh_custom_viewer(ctx.widget) # 手动刷新伪代码窗口，触发UI Hook
        

def clear_color_by_ctx(ctx):
    global MARKED_LINES
    vu = ida_hexrays.get_widget_vdui(ctx.widget) # 只有伪代码会返回vdui_t，不然返回None
    if vu:
        loc = ida_moves.lochist_entry_t()
        if ida_kernwin.get_custom_viewer_location(loc, ctx.widget):
            coord = pseudo_line_t(vu.cfunc.entry_ea, _place_to_line_number(loc.place()))
            
            if coord in MARKED_LINES.keys():
                del MARKED_LINES[coord]
                ida_kernwin.refresh_custom_viewer(ctx.widget)

def get_color_by_ctx(ctx) -> str:
    global MARKED_LINES
    vu = ida_hexrays.get_widget_vdui(ctx.widget) # 只有伪代码会返回vdui_t，不然返回None
    if vu:
        loc = ida_moves.lochist_entry_t()
        if ida_kernwin.get_custom_viewer_location(loc, ctx.widget):
            coord = pseudo_line_t(vu.cfunc.entry_ea, _place_to_line_number(loc.place()))
            
            if coord in MARKED_LINES.keys():
                return MARKED_LINES[coord]

    return ''

# 这个是为了高亮函数调用链编写的
def set_color_for_funcaddr_list(funcaddrs:list):
    global PATH_COLOR_INDEX
    
    color = ['orange', 'green', 'yellow', 'pink']
    index = 0
    for call_chain in funcaddrs:
        if call_chain.call_ea != 0:
            set_color_by_ea(call_chain.call_ea, color[PATH_COLOR_INDEX])
    # set_ea_comment(call_chain.call_ea, f"The {PATH_COLOR_INDEX} path.")
    PATH_COLOR_INDEX += 1
    PATH_COLOR_INDEX = PATH_COLOR_INDEX if PATH_COLOR_INDEX < len(color) else 0 # 最长为index-1

# 清除函数调用链的高亮
def clear_color_for_funcnaddr_list(funcnames:list):
    pass

# -------------------------------------------------------------
#                     自定义函数 - 路径遍历
# -------------------------------------------------------------

def find_all_call_chains(start_ea, end_ea):
    global ALL_PATH, START_ADDR, TARGET_ADDR
    """
    在IDA中查找从起始函数到目标函数的所有调用链。
    """
    
    clear_color()
    START_ADDR = -1
    TARGET_ADDR = -1
    
    start_func = ida_funcs.get_func(start_ea)
    end_func = ida_funcs.get_func(end_ea)

    if not start_func or not end_func:
        ida_kernwin.info(f"VulnHunter: Error, Not valid function address.\n")
        return

    start_ea = start_func.start_ea
    end_ea = end_func.start_ea
    start_name = ida_funcs.get_func_name(start_ea)
    end_name = ida_funcs.get_func_name(end_ea)

    ida_kernwin.msg(f"VulnHunter: Searching call chain from {start_name}(0x{start_ea:x}) to {end_name}(0x{end_ea:x}).\n")

    ALL_PATH = []
    # 我们用call_ea=0来表示起始节点没有调用来源。
    initial_path = [CallChainLink(0, start_ea)]
    _find_paths_recursive(start_ea, end_ea, initial_path)

    if not ALL_PATH:
        ida_kernwin.info(f"VulnHunter: No valid call chain found.\n")
    else:
        ida_kernwin.msg(f"VulnHunter: {len(ALL_PATH)} nums call chain found:\n")
        for i, path in enumerate(ALL_PATH):
            path_parts = []
            for j, link in enumerate(path):
                func_name = ida_funcs.get_func_name(link.func_ea)
                if j == 0:
                    # 路径的第一个元素是起始函数
                    path_parts.append(f"{func_name}(0x{link.func_ea:x})")
                else:
                    # 后续的元素包含了调用地址，格式化输出
                    path_parts.append(f" -> {func_name}(0x{link.func_ea:x})")

            path_str = "".join(path_parts)
            ida_kernwin.msg(f"  Call Chain {i+1}: {path_str}\n")
            
    ida_kernwin.msg("VulnHunter: Search complete.\n")


def _find_paths_recursive(current_ea, target_ea, current_path):
    """
    基于DFS递归
    其中：current_path表示当前寻找的这条路径，为一个由 CallChainLink 对象组成的列表
    ALL_PATH是列表的列表，存放的是所有的路径
    """
    global ALL_PATH
    
    # 如果说当前的地址已经在当前寻找的路里面了，说明遇到环路，则不要这条路
    # 需要从path中的对象里提取函数地址进行比较。我们排除最后一个元素（即current_ea自身）以进行正确的环路判断。
    if current_ea in [link.func_ea for link in current_path[:-1]]:
        return
    
    # 如果当前节点就是目标节点，则找到一条路
    if current_ea == target_ea:
        ALL_PATH.append(current_path)
        return

    # 查找当前函数调用的其他函数
    callees = set() # 想了想还是用set而不是list :)
    func = ida_funcs.get_func(current_ea)
    if not func:
        return # 一般不会出现这个情况但是以防万一
    
    # 我们查找当前函数调用的其他函数的方法是，检查这个函数内部所有可以被交叉引用的内容，这就只包括变量和函数。然后筛选出函数就可以。
    fii = idaapi.func_item_iterator_t(func) # 使用迭代器遍历函数内部所有内容
    while fii.next_code():
        head = fii.current() # 当前指令的地址
        x = ida_xref.xrefblk_t() # 准备一个存放交叉引用信息的对象
        ok = x.first_from(head, ida_xref.XREF_ALL) # ok这个引用表示，head这个地址的指令的目标和类型
        while ok:
            
            # CN:call near，CF:call far。函数调用一般只有这两种类型
            if x.type == ida_xref.fl_CN or x.type == ida_xref.fl_CF:
                callee_func = ida_funcs.get_func(x.to) # 获取这个函数对象
                if callee_func:
                    callees.add(CallChainLink(head, callee_func.start_ea))
            ok = x.next_from() # 查找下一个
    
    for callee_link in list(callees):
        # 将新节点加入路径，并把新路径传递给下一次递归
        _find_paths_recursive(callee_link.func_ea, target_ea, current_path + [callee_link])


# -------------------------------------------------------------
#                     自定义函数 - 注释
# -------------------------------------------------------------

def set_ea_comment(ea, comment):
    current_widget = ida_kernwin.get_current_widget()
    if ida_kernwin.get_widget_type(current_widget) != idaapi.BWN_PSEUDOCODE:
        ida_kernwin.msg("VulnHunter: Please make sure the pseudocode view is the active window.\n")
    else:
        # 获取 Hex-Rays 视图对象 (vdui_t)
        vdui = ida_hexrays.get_widget_vdui(current_widget)
        if vdui:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                tl = idaapi.treeloc_t()
                tl.ea = ea  # 在指定地址添加注释
                tl.itp = idaapi.ITP_SEMI # 在分号后，即行尾添加
                
                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()
                vdui.refresh_view(True)
                

# -------------------------------------------------------------
#                     自定义函数 - 端口
# -------------------------------------------------------------
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)
    
    def log_message(self, format, *args):
        """重写此方法以屏蔽日志输出。"""
        pass

def open_port_for_mcp():
    with SimpleXMLRPCServer(('localhost', MCP_PORT), requestHandler=RequestHandler, allow_none=True) as server:
        server.register_introspection_functions()
        ida_kernwin.msg(f"VulnHunter: MCP RPC Server listening on port {MCP_PORT}\n")

        # 注册函数，使其能通过RPC被外部调用
        server.register_function(_get_function_name_by_addr, 'get_function_name_by_addr')

        # 定义一个简单的ping函数用于检查服务器是否存活
        def ping():
            ida_kernwin.msg(f"VulnHunter: MCP server installed correctly.\n")
            return "pong"
        
        rpc_functions = {
            'ping': ping,
            'get_function_addr_by_name': _get_function_addr_by_name,
            'get_metadata': _get_metadata,
            'decompile_function': _decompile_function,
            'disassemble_function': _disassemble_function,
            'find_call_chain': _find_call_chain,
            'find_xrefs_with_constant': _find_xrefs_with_constant,
            'find_context_xrefs': _find_context_xrefs,
            'list_import_table_functions': _list_import_table_functions,
            'list_export_table_functions': _list_export_table_functions,
        }
        
        for funcname in rpc_functions.keys():
            server.register_function(rpc_functions[funcname], funcname)

        try:
            server.serve_forever()
        except Exception as e:
            ida_kernwin.msg(f"VulnHunter: RPC server encountered an error: {e}\n")
            

# -------------------------------------------------------------
#           自定义函数 - 高级交叉引用 - 常量参数筛选
# -------------------------------------------------------------

# 利用交叉引用，获取当前光标的函数名称
def get_function_name_at_cursor():
    current_ea = ida_kernwin.get_screen_ea()
    
    if current_ea == idaapi.BADADDR:
        return None

    x = ida_xref.xrefblk_t()
    ok = x.first_from(current_ea, ida_xref.XREF_ALL)
    while ok:
        if x.type == ida_xref.fl_CN or x.type == ida_xref.fl_CF:
            callee_func = ida_funcs.get_func(x.to)
            if callee_func:
                callee_name = ida_funcs.get_func_name(callee_func.start_ea)
                return (callee_name, callee_func.start_ea)
        ok = x.next_from()

    enclosing_func = ida_funcs.get_func(current_ea)
    if enclosing_func and enclosing_func.start_ea <= current_ea < enclosing_func.end_ea:
        enclosing_name = ida_funcs.get_func_name(enclosing_func.start_ea)
        return (enclosing_name, enclosing_func.start_ea)
    return None


def get_decompiled_line(cfunc, ea):
    """
    从一个反编译对象(cfunc)中获取指定地址(ea)对应的伪代码行。
    """
    if ea not in cfunc.eamap:
        ida_kernwin.msg(f"VulnHunter: An unknown error happens: The ea 0x{ea:x} seems not to be in the function.\n")
        return None

    insnvec = cfunc.eamap[ea] # 获取AST
    lines = []
    for stmt in insnvec:
        # 使用 qstring_printer_t 将 AST 节点转换为字符串
        qp = ida_hexrays.qstring_printer_t(cfunc, False)
        stmt._print(0, qp)
        s = qp.s.split('\n')[0]
        lines.append(s)
    
    return '\n'.join(lines)

def find_advanced_xrefs(target_ea):
    """
    通过ea，找到交叉引用它的伪代码行。
    返回值暂定为一个列表，每个列表里面是个字典：）
    """
    if not ida_hexrays.init_hexrays_plugin():
        ida_kernwin.msg('VulnHunter: You seem not to have a decompiler. Please check your IDA setup.\n')
        return None

    results = []
    
    # 找到所有引用到 target_ea 的来源地址
    try:
        referencing_addresses = [x.frm for x in idautils.XrefsTo(target_ea)]
    except:
        return [] # 没有找到那肯定为空了

    # 遍历每一个引用来源
    for ref_ea in referencing_addresses:
        # 反编译包含该引用的函数
        try:
            cfunc = ida_hexrays.decompile(ref_ea)
        except ida_hexrays.DecompilationFailure:
            cfunc = None

        if not cfunc:
            ida_kernwin.msg("VulnHunter: Compilation Failed. You should check your IDA setup.\n")
            continue
        
        # 获取引用地址对应的伪代码行
        line_text = get_decompiled_line(cfunc, ref_ea)
        if line_text is None:
            continue
            
        # 获取函数名并组合结果
        function_name = ida_funcs.get_func_name(cfunc.entry_ea) or ""
        
        results.append({
            'address': ref_ea,
            'function': function_name,
            'line': line_text.strip()
        })
        
    return results

# 点击交叉引用的表格会触发这个函数，使得其跳转到指定地址
def xrefs_table_jump(selected_item):
    address = selected_item[0]
    try:
        # ida_kernwin.msg(f"Jump!\n")
        address_ea = int(address, 16)
        ida_kernwin.jumpto(address_ea)
    except (ValueError, TypeError):
        ida_kernwin.msg(f"VulnHunter: jump to address 0x{address} failed.\n")

# 判断是否有常量参数
def has_constant_argument(code_line: str, function_name: str) -> bool:
    pattern = re.compile(r"\b" + re.escape(function_name) + r"\s*\((.*)\)")
    match = pattern.search(code_line)

    if not match:
        return False

    args_str = match.group(1)
    if not args_str.strip():
        return False

    args = args_str.split(',')
    

    # 遍历每个参数，检查其是否为常量
    for arg in args:
        arg = arg.strip() # 去除参数两边的空格

        # 检查是否为字符串字面量
        if arg.startswith('"') and arg.endswith('"'):
            return True
            
        if arg.startswith("'") and arg.endswith("'"):
            return True
        
        # 检查是不是数字
        try:
            if arg.lower().startswith('0x'):
                int(arg, 16)
            else:
                float(arg)
            return True
        except ValueError:
            continue

    return False


# -------------------------------------------------------------
#           自定义函数 - 高级交叉引用 - 上下文函数筛选
# -------------------------------------------------------------

# 查找所有调用了 xref_addr 的函数，并检查这些函数是否也调用了 target_addr。
def get_context_function(xref_addr, target_addr):
    """
    查找所有调用了 xref_addr 的函数，并检查这些函数是否也调用了 target_addr。
    """
    # 获取并验证两个输入地址对应的函数
    xref_func = ida_funcs.get_func(xref_addr)
    target_func = ida_funcs.get_func(target_addr)

    if not xref_func or not target_func:
        ida_kernwin.msg("VulnHunter: One or both provided addresses are not in a valid function.\n")
        return []

    xref_start_ea = xref_func.start_ea
    target_start_ea = target_func.start_ea

    # 找到所有对 xref_addr 的交叉引用，并按其所在的父函数进行分组
    callers_of_xref = {}
    try:
        for xref in idautils.XrefsTo(xref_start_ea):
            caller_func = ida_funcs.get_func(xref.frm)
            if caller_func:
                caller_ea = caller_func.start_ea
                if caller_ea not in callers_of_xref:
                    callers_of_xref[caller_ea] = []
                callers_of_xref[caller_ea].append(xref.frm)
    except:
        return []

    # 遍历这些父函数，检查它们是否也调用了 target_addr
    results = []
    for caller_ea, original_xref_locations in callers_of_xref.items():
        caller_func_obj = ida_funcs.get_func(caller_ea)
        if not caller_func_obj:
            continue

        calls_target_func = False
        fii = idaapi.func_item_iterator_t(caller_func_obj)
        while fii.next_code():
            instruction_ea = fii.current()
            x = ida_xref.xrefblk_t()
            ok = x.first_from(instruction_ea, ida_xref.XREF_ALL)
            while ok:
                if x.type == ida_xref.fl_CN or x.type == ida_xref.fl_CF:
                    callee_func = ida_funcs.get_func(x.to)
                    if callee_func and callee_func.start_ea == target_start_ea:
                        calls_target_func = True
                        break
                ok = x.next_from()
            if calls_target_func:
                break
        
        # 如果该父函数满足条件，则处理其对 xref_addr 的所有交叉引用:)
        if calls_target_func:
            try:
                cfunc = ida_hexrays.decompile(caller_ea)
            except ida_hexrays.DecompilationFailure:
                cfunc = None

            if not cfunc:
                ida_kernwin.msg(f"VulnHunter: Decompilation failed for function at 0x{caller_ea:x}.\n")
                continue
            
            function_name = ida_funcs.get_func_name(cfunc.entry_ea) or ""
            
            # 为了满足渲染表格，生成字典
            for ref_ea in original_xref_locations:
                line_text = get_decompiled_line(cfunc, ref_ea)
                if line_text:
                    results.append({
                        'address': ref_ea,
                        'function': function_name,
                        'line': line_text.strip()
                    })
            
    return results

# -------------------------------------------------------------
#                     动作部分
# -------------------------------------------------------------

class SetStartAddrAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        global START_ADDR, COLORS
        func = ida_funcs.get_func(ctx.cur_ea)
        
        if func and func.start_ea == ctx.cur_ea:
            if START_ADDR == -1:
                START_ADDR = ctx.cur_ea
                set_color_by_ctx(ctx, 'blue')
                ida_kernwin.msg(f"VulnHunter: The startaddr is set to 0x{START_ADDR:x}.\n")
            elif START_ADDR == ctx.cur_ea: # 若这个本来就标记为起始地址了，那么清除一下:)
                START_ADDR = -1
                clear_color_by_ctx(ctx)
                ida_kernwin.msg(f"VulnHunter: Clear Success.\n")
            else:                          # 这个情况应该是，在别的函数重新设置了起始地址
                delete_item = None
                for i in MARKED_LINES.keys():
                    if MARKED_LINES[i] == 'blue': # 删除以前的START_ADDR
                        delete_item = i
                del MARKED_LINES[delete_item]
                ida_kernwin.msg(f"The MARKED_LINES: {MARKED_LINES}\n")
                ida_kernwin.msg(f"VulnHunter: The old start addr 0x{START_ADDR:x} is clear.\n")
                START_ADDR = ctx.cur_ea
                set_color_by_ctx(ctx, 'blue')
                ida_kernwin.msg(f"VulnHunter: The startaddr is set to 0x{START_ADDR:x}.\n")
                
        else:
            ida_kernwin.info("You should check.\n")
        
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE

class SetDestAddrAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        
    def activate(self, ctx):
        global TARGET_ADDR, COLORS
        func = ida_funcs.get_func(ctx.cur_ea)
        
        if func and func.start_ea == ctx.cur_ea:
            if TARGET_ADDR== -1:
                TARGET_ADDR = ctx.cur_ea
                set_color_by_ctx(ctx, 'red')
                ida_kernwin.msg(f"VulnHunter: The targetaddr is set to 0x{TARGET_ADDR:x}.\n")
            elif TARGET_ADDR == ctx.cur_ea: # 若这个本来就标记为起始地址了，那么清除一下:)
                TARGET_ADDR = -1
                clear_color_by_ctx(ctx)
                ida_kernwin.msg(f"VulnHunter: Clear Success.\n")
            else:                          # 这个情况应该是，在别的函数重新设置了起始地址
                delete_item = None
                for i in MARKED_LINES.keys():
                    if MARKED_LINES[i] == 'red': # 删除以前的TARGET_ADDR
                        delete_item = i
                del MARKED_LINES[delete_item]
                ida_kernwin.msg(f"The MARKED_LINES: {MARKED_LINES}\n")
                ida_kernwin.msg(f"VulnHunter: The old start addr 0x{TARGET_ADDR:x} is clear.\n")
                TARGET_ADDR = ctx.cur_ea
                set_color_by_ctx(ctx, 'red')
                ida_kernwin.msg(f"VulnHunter: The startaddr is set to 0x{TARGET_ADDR:x}.\n")

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class HuntAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        global PATH_INDEX
        
        find_all_call_chains(START_ADDR, TARGET_ADDR)
        PATH_INDEX = 0
        return 1
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
    
class NextPathAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        global PATH_INDEX
        
        # ida_kernwin.msg(f"The index: {PATH_INDEX}.\n")
        
        clear_color()
        set_color_for_funcaddr_list(ALL_PATH[PATH_INDEX])
        PATH_INDEX += 1
        if PATH_INDEX == len(ALL_PATH):
            clear_color()
            PATH_INDEX = 0
        return 1
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
    
class ConstantXrefsAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        func_name, ea = get_function_name_at_cursor()
        func = ida_funcs.get_func(ea)
        
        # ida_kernwin.msg(f"The func_name: {func_name}, ea: 0x{ea:x}.\n")
        if not func:
            return
        
        
        xrefs_list = find_advanced_xrefs(ea)
        xrefs_data_ = [[hex(i['address']), i['function'], i['line']] for i in xrefs_list]
        xrefs_data = []
        
        for line in xrefs_data_:
            code = line[2]
            if has_constant_argument(code, func_name):
                xrefs_data.append(line)
        
        c = XrefsTable(
            f"vulnhunter constant xrefs to {func_name}",
            items=xrefs_data,
            on_ok_callback=xrefs_table_jump
        )
        
        c.show()
        
        return 1
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# 设置危险函数的地址
class SetContextXrefsAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        global DANGER_ADDR
        func_name, ea = get_function_name_at_cursor()
        DANGER_ADDR = ea
        ida_kernwin.msg(f"VulnHunter: The dangerous function is set to {func_name}(0x{DANGER_ADDR:x}).\n")
        return 1
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ContextXrefsAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        if DANGER_ADDR == -1:
            ida_kernwin.msg(f"VulnHunter: The dangerous function is not set. Please set it first.\n")
            return 
        
        func_name, ea = get_function_name_at_cursor()
        func = ida_funcs.get_func(ea)
        
        # ida_kernwin.msg(f"The func_name: {func_name}, ea: 0x{ea:x}.\n")
        if not func:
            return
        
        xrefs_list = get_context_function(ea, DANGER_ADDR)
        # print(xrefs_list)
        
        xrefs_data = [[hex(i['address']), i['function'], i['line']] for i in xrefs_list]
        
        c = XrefsTable(
            f"vulnhunter context xrefs to {func_name}",
            items=xrefs_data,
            on_ok_callback=xrefs_table_jump
        )
        
        c.show()
        
        return 1
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class TestAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        
        print(get_context_function(0x1169, 0x11A7))
        return 1
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# 这个是点击交叉引用表格时，跳转到交叉引用的地方的一个动作
class XrefsTableJumpsAction(ida_kernwin.action_handler_t):
    def __init__(self, thing):
        ida_kernwin.action_handler_t.__init__(self)
        self.thing = thing

    def activate(self, ctx):
        sel = []
        for idx in ctx.chooser_selection:
            sel.append(str(idx))

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ida_kernwin.is_chooser_widget(ctx.widget_type) \
          else ida_kernwin.AST_DISABLE_FOR_WIDGET

    @staticmethod
    def compose_action_name(v):
        return "choose:act%s" % v


# -------------------------------------------------------------
#                     UI 部分
# -------------------------------------------------------------

class RightMouseHook(ida_kernwin.UI_Hooks):
    
    # 这个函数就是在右键菜单生成结束的时候调用的：）
    def finish_populating_widget_popup(self, widget, popup_handle):
        """
        右键菜单弹出时，附加几个动作
        widget表示窗口
        popup_handle表示正在被构建的右键菜单本身
        """
        call_chain_action_names = [
            "vulnHunter::SetStartAddr",
            "vulnHunter::SetDestAddr",
            'vulnHunter::Hunt',
        ]
        
        xrefs_action_names = [
            'vulnHunter::ConstantXrefs',
            'vulnHunter::SetDangerFunction',
            'vulnHunter::ContextXrefs',
            # 'vulnHunter::Test',
        ]
        
        for action_name in call_chain_action_names:
            ida_kernwin.attach_action_to_popup(
                widget=widget,                            # 当前窗口
                popup_handle=popup_handle,                # 当前右键菜单
                name=action_name,                         # 附加所有注册的动作名称
                popuppath='VulnHunter:CallChain/'         # 位于右键菜单的VulnHunter/下 
            )
        
        for action_name in xrefs_action_names:
            ida_kernwin.attach_action_to_popup(
                widget=widget,                  # 当前窗口
                popup_handle=popup_handle,      # 当前右键菜单
                name=action_name,               # 附加所有注册的动作名称
                popuppath='VulnHunter:Xrefs/'   # 位于右键菜单的VulnHunter/下 
            )
            
class pseudocode_lines_rendering_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)
        # self.marked_lines = {}
    
    # 当IDA重绘反编译窗口时会调用这个函数
    def get_lines_rendering_info(self, out, widget, rin):
        global MARKED_LINES
        vu = ida_hexrays.get_widget_vdui(widget) # 返回当前窗口，不是伪代码窗口都会返回None
        if vu:
            entry_ea = vu.cfunc.entry_ea
            
            # 遍历所有即将被渲染的行
            for section_lines in rin.sections_lines:
                for line in section_lines:
                    coord = pseudo_line_t(
                        entry_ea,
                        _place_to_line_number(line.at))
                    color = MARKED_LINES.get(coord, None)
                    if color is not None:
                        color_num = COLORS[color]
                        e = ida_kernwin.line_rendering_output_entry_t(line) # 获得该行的渲染条目
                        e.bg_color = color_num
                        out.entries.push_back(e) # 将修改后的渲染条目添加到输出列表out，覆盖样式
                        

# 交叉引用的表格部分
class XrefsTable(Choose):
    def __init__(self,
                 title,
                 items,
                 on_ok_callback=None,
                 modal=False):
        Choose.__init__(
            self,
            title,
            [ ["Address", 15], ["Function", 30], ["Code", 50] ],
            Choose.CH_RESTORE | Choose.CH_CAN_EDIT,
            )

        self.items = items
        self.on_ok = on_ok_callback
        self.modal = modal
        self.icon = 5

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        if self.on_ok:
            self.on_ok(self.items[n])
        return (Choose.NOTHING_CHANGED,)

    def OnEditLine(self, n):
        pass

    def OnClose(self):
        pass

    def show(self):
        return self.Show(self.modal)



# ida扫描到该函数的时候，才会认为这是一个插件，因此必须存在，且返回加载器
def PLUGIN_ENTRY():
    return VulnHunter()


# -------------------------------------------------------------
#                         mcp部分
# -------------------------------------------------------------

def mcp_rpc(flag=ida_kernwin.MFF_READ):
    """
    一个装饰器，用于将任何函数的执行都调度到IDA主线程。
    它处理了返回值和异常的线程间传递。
    
    Args:
        flag: MFF_READ (默认) 或 MFF_WRITE，用于ida_kernwin.execute_sync。
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # 用于在线程间传递结果的容器
            result_container = {
                'retval': None,
                'exception': None
            }

            def execute_in_main_thread():
                try:
                    # 在主线程中执行原始函数
                    result_container['retval'] = func(*args, **kwargs)
                except Exception as e:
                    # 如果发生异常，捕获它
                    result_container['exception'] = e

            # 调度执行
            ida_kernwin.execute_sync(execute_in_main_thread, flag)

            # 执行完毕后，检查是否发生了异常
            if result_container['exception']:
                # 如果有异常，在当前RPC线程中重新引发它
                # xmlrpc库会自动将此异常打包成Fault发回给客户端
                raise result_container['exception']

            # 如果没有异常，返回结果
            return result_container['retval']
        return wrapper
    return decorator


@mcp_rpc()
def _get_function_name_by_addr(addr):
    return ida_funcs.get_func_name(addr)

@mcp_rpc()
def _get_function_addr_by_name(name):
    return idc.get_name_ea_simple(name)


@mcp_rpc()
def _get_metadata():
    class IDAMetadata:
        def __init__(self):
            self.path = idaapi.get_input_file_path()
            self.module = idaapi.get_root_filename()
            self.base = hex(idaapi.get_imagebase())
            self.md5 = ida_nalt.retrieve_input_file_md5()
            self.sha256 = ida_nalt.retrieve_input_file_sha256()
            self.crc32 = hex(ida_nalt.retrieve_input_file_crc32())
            self.filesize = hex(ida_nalt.retrieve_input_file_size())
        def __repr__(self):
            return f"IDAMetadata(path={self.path}, module={self.module}, base={self.base}, md5={self.md5}, sha256={self.sha256}, crc32={self.crc32}, filesize={self.filesize})"
    return IDAMetadata()

@mcp_rpc()
def _decompile_function(address):
    func = ida_funcs.get_func(address)
    cfunc = ida_hexrays.decompile(func)
    return str(cfunc)

@mcp_rpc()
def _disassemble_function(start_address):
    disassembly_code = ""
    if not start_address == idc.BADADDR:
        # disassembly_code += f"Disassembly for function '{start_address}':\n"
        for instruction_ea in idautils.FuncItems(start_address):
            disassembly_line = idc.GetDisasm(instruction_ea)
            disassembly_code += f"  {hex(instruction_ea)}: {disassembly_line}\n"
    return disassembly_code

@mcp_rpc()
def _find_call_chain(start_func, target_func):
    start_ea = idc.get_name_ea_simple(start_func)
    target_ea = idc.get_name_ea_simple(target_func)
    
    find_all_call_chains(start_ea, target_ea)
    return_paths = []
    
    for i, path in enumerate(ALL_PATH):
        path_parts = []
        for j, link in enumerate(path):
            func_name = ida_funcs.get_func_name(link.func_ea)
            if j == 0:
                # 路径的第一个元素是起始函数
                path_parts.append(f"{func_name}(0x{link.func_ea:x})")
            else:
                # 后续的元素包含了调用地址，格式化输出
                path_parts.append(f" -> {func_name}(0x{link.func_ea:x})")

        path_str = "".join(path_parts)
        return_paths.append(f"  Call Chain {i+1}: {path_str}")
    
    return return_paths

@mcp_rpc()
def _find_xrefs_with_constant(function_name):
    ea = idc.get_name_ea_simple(function_name)
    if ea == idc.BADADDR:
        return []
    
    xrefs_list = find_advanced_xrefs(ea)
    xrefs_data_ = [[hex(i['address']), i['function'], i['line']] for i in xrefs_list]
    xrefs_data = []
    
    for line in xrefs_data_:
        code = line[2]
        if has_constant_argument(code, function_name):
            item = {
                'address': line[0],
                'function': line[1],
                'code': line[2]
            }
            xrefs_data.append(item)
    
    return xrefs_data

@mcp_rpc()
def _find_context_xrefs(function_name, danger_function_name):
    danger_ea = idc.get_name_ea_simple(danger_function_name)
    if danger_ea == idc.BADADDR:
        return []
    
    ea = idc.get_name_ea_simple(function_name)
    if ea == idc.BADADDR:
        return []
    
    xrefs_list = get_context_function(ea, danger_ea)
    
    return xrefs_list


@mcp_rpc()
def _list_import_table_functions():
    imports = []
    nimps = ida_nalt.get_import_module_qty()  # Get the number of import modules
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            continue
        def callback(ea, name, ordinal):
            if name:
                imports.append({
                    'module': module_name,
                    'function': name,
                    'address': hex(ea)
                })
            return True
        ida_nalt.enum_import_names(i, callback)
    return imports


@mcp_rpc()
def _list_export_table_functions():
    exports = []
    for entry in idautils.Entries():
        ordinal, func_ea, _, func_name = entry
        exports.append({
            'function': func_name,
            'address': hex(func_ea)
        })
    return exports

