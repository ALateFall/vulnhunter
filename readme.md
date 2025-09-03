# VulnHunter - An Assistant Plugin for IDA Pro Vulnerability Hunting 🛠

 [中文](https://github.com/ALateFall/vulnhunter/blob/master/readme_ch.md) | English

VulnHunter is an IDA Pro plugin designed for reverse engineers and vulnerability researchers to significantly improve the efficiency and depth of binary vulnerability analysis. It automates tedious manual analysis workflows through a series of powerful enhancements and introduces the analytical capabilities of Large Language Models (LLMs) based on MCP, opening up new possibilities for vulnerability hunting.

⚠️ **Project Status:** This project is under active development. We welcome you to contribute by submitting [Issues](https://github.com/ALateFall/vulnhunter/issues) or Pull Requests!

### 🌟 What does VulnHunter do? 🤠

- **Call Chain Visualization:** Say goodbye to manually tracing function calls. Highlight the complete call path from a starting point to a destination with a single click.
- **Advanced Cross-References:** Go beyond IDA Pro's native capabilities with complex and customizable cross-reference queries.
- **LLM-Powered Analysis:** Integrates a custom Machine Code Protocol (MCP) to bring powerful AI models into your reverse engineering workflow, enabling automated taint analysis and dangerous function identification.
- **Efficient Shortcuts:** Thoughtfully designed hotkeys allow you to switch between different call chains and analysis paths smoothly.

### ✨ Main Features

#### 1. Highlight Call Chain 😀

In a complex binary, manually tracing a function's call sources or its ultimate impact is extremely time-consuming and error-prone. VulnHunter completely changes this.

- **Start/End Point Selection:** Simply select a start function and a target function in the disassembly or decompilation view.
- **One-Click Highlighting:** The plugin automatically calculates and highlights all possible call chains connecting the two functions, printing the results to the Output window.
- **Path Switching:** When multiple call paths exist, you can use the hotkey (**Shift+I**) to quickly switch between and preview different call chains.

#### 2. Advanced Cross-References 😄

IDA Pro's native cross-references (Xrefs) are powerful but relatively basic. VulnHunter builds an advanced query engine on top of them, allowing you to filter cross-references in a more granular and semantic way.

- **Constant Argument Filtering** Sometimes, we want to filter cross-references to functions that are called with a specific constant argument, such as the `7` in `mprotect(addr, length, 7)`. VulnHunter supports solving this problem through advanced cross-references. With VulnHunter, you can quickly find all locations where a function is called with a specific constant argument.
- **Contextual Function Filtering** VulnHunter supports context-based cross-referencing, which allows you to filter for callers of a target function that *also* call another specified function. By setting a "dangerous function," you can filter cross-references to find only those that also invoke that dangerous function.

#### 3. Custom MCP & LLM Integration 🤖

By leveraging a custom Machine Code Protocol (MCP) based on fastMCP, we seamlessly integrate IDA Pro's deep binary analysis capabilities with the reasoning power of Large Language Models (LLMs).

- **Functionality Exposure:** The plugin exposes its core "Find Call Chain" and "Advanced Cross-References" features as an API to the LLM.
- **Automated Taint Analysis:** Combined with the **Highlight Call Chain** feature, you can let an LLM act as your taint analysis engine. Simply provide the LLM with a taint source and sink, and it will automatically call VulnHunter's API to find and analyze potential taint propagation paths, achieving end-to-end vulnerability discovery.
- **Intelligent Dangerous Function Identification:** Combined with the **Advanced Cross-References** feature, an LLM can automatically execute complex queries. For example, you can write a prompt that instructs the LLM to find all calls to `memcpy` where the length argument originates from user input and analyze if a buffer overflow risk exists.

Currently, VulnHunter's IDA Pro MCP has implemented the following IDA Pro interfaces:

- `get_function_name_by_addr`: Get the function name from a given address.
- `get_function_addr_by_name`: Get the function address from a given name.
- `get_metadata`: Get metadata about the IDA project, such as architecture, version, decompiler status, etc.
- `decompile_function`: Get the pseudo-code for a function at a specified address. This requires an active IDA Pro decompiler.
- `disassemble_function`: Get the assembly code for a function at a specified address.
- `find_call_chain`: Find the function call chain from a start function name to a destination function name. This is a core feature of VulnHunter.
- `find_xrefs_with_constant`: Find cross-references to a function that must include a specific constant argument. This is a core feature of VulnHunter.
- `find_context_refs`: Find cross-references where the calling function must also contain a call to another specified function. This is a core feature of VulnHunter.
- `list_import_table_functions`: List the functions in the program's import table.
- `list_export_table_functions`: List the functions in the program's export table.

### 🔧 Installation and Configuration

**Prerequisites**

- IDA Pro 9.0 or newer.
- Python 3.11 or newer (the version bundled with IDA Pro is recommended).
- (Optional, for LLM features) A platform that can invoke MCP, such as `cline`.
- (Optional, for LLM features) A valid LLM API Key (e.g., OpenAI, Anthropic, or a locally deployed model API).

**Installation Steps**

1. **Download the Plugin:**

   - Download the two `.py` files from this project: `vulnhunter.py` and `vulnhunter_mcp.py`.

2. **Install the Plugin:**

   - Copy both `vulnhunter.py` and `vulnhunter_mcp.py` files into your IDA Pro `plugins` directory.
     - **Windows:** `IDA Pro\plugins`
     - **Linux/macOS:** `~/.idapro/plugins`

3. (Optional, for MCP usage) Install the MCP functionality with the following command:

   ```bash
   pip install git+https://github.com/ALateFall/vulnhunter.git
   ```

   Then, add the following configuration to your `cline` MCP settings:

   ```json
   {
     "mcpServers": {
       "vulnhunter": {
         "disabled": false,
         "timeout": 60,
         "type": "stdio",
         "command": "vulnhunter"
       }
     }
   }
   ```

### 🚀 Usage Guide

1. Start IDA Pro and load your target binary.
2. (Optional, for MCP usage) Open your MCP platform (e.g., `cline`). VulnHunter will automatically connect to your platform. (You may need to refresh the MCP connection).
3. Use the features as needed:
   - **Highlight Call Chain**: In the disassembly view, right-click the starting address of the source function and select **VulnHunter:CallChain/set as start address**. Then, right-click on the destination function and select **VulnHunter:CallChain/set as target address**. Once both addresses are set, right-click anywhere and select **VulnHunter:CallChain/start to find call chains**. All call chains will be printed in the Output window. Use **Shift+I** to cycle through highlighting the different chains.
   - **Advanced Cross-References**:
     - For filtering by **constant arguments**, right-click on the function and select **VulnHunter:Xrefs/find xrefs with constant values** to filter for calls with constant parameters. The hotkey **Ctrl+X** has the same effect.
     - For **contextual filtering**, first use **VulnHunter:Xrefs/set danger function** to set the dangerous function. Then, you can use **VulnHunter:Xrefs/find context xrefs** to find cross-references where the caller also invokes the designated dangerous function.

### 🤝 How to Contribute

We warmly welcome any contributions from the community! Whether you are submitting bug reports, suggesting new features, or contributing code directly, your input will have a positive impact on this project.

### 📜 License

This project is licensed under the [MIT License](https://github.com/ALateFall/vulnhunter/blob/master/LICENSE).

------

**Disclaimer:** This tool is intended for authorized security research and educational purposes only. The user is responsible for all of their actions.