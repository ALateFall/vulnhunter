from mcp.server.fastmcp import FastMCP
import socket
import xmlrpc.client

PORT = 9673
HOST = 'localhost'
SERVER_URL = f"http://{HOST}:{PORT}/RPC2"
mcp = FastMCP()
ida_server = None

@mcp.tool()
def get_function_name_by_addr(address: int) -> str:
    '''
    通过函数地址获得函数名称
    '''
    return ida_server.get_function_name_by_addr(address)

@mcp.tool()
def get_function_addr_by_name(name: str) -> int:
    '''
    通过函数名称获得函数地址
    '''
    return ida_server.get_function_addr_by_name(name)

@mcp.tool()
def get_metadata():
    '''
    获得IDA项目的元数据
    '''
    return ida_server.get_metadata()

@mcp.tool()
def decompile_function(address: int) -> str:
    '''
    获得指定地址函数的伪代码
    '''
    return ida_server.decompile_function(address)

@mcp.tool()
def disassemble_function(address: int) -> str:
    '''
    获得指定地址函数的汇编代码
    '''
    return ida_server.disassemble_function(address)

@mcp.tool()
def find_call_chain(start_func_name:str, target_func_name:str) -> list:
    '''
    找出从起始函数到目标函数的函数调用链
    '''
    return ida_server.find_call_chain(start_func_name, target_func_name)

def check_mcp_connection() -> bool:
    """
    检查是否能成功连接到IDA Pro中运行的RPC服务器。
    """
    global ida_server
    try:
        print(f"Attempting to connect to IDA RPC server at {SERVER_URL}...")
        proxy = xmlrpc.client.ServerProxy(SERVER_URL, allow_none=True)
        # 尝试调用一个简单的ping函数
        response = proxy.ping()
        if response == "pong":
            ida_server = proxy # 连接成功，赋值给全局变量
            return True
        else:
            return False
    except (ConnectionRefusedError, socket.gaierror, xmlrpc.client.ProtocolError) as e:
        return False
    

def main():
    if check_mcp_connection():
        mcp.run(transport='stdio')

if __name__ == "__main__":
    main()