# capa-explorer

Capa explorer for Cutter.

The goal of this is to port the functionality of the [capa IDA plugin](https://github.com/fireeye/capa/tree/master/capa/ida/plugin) to Cutter. 

## Features

- Display capa results in an interactive tree view of rule matches and their locations in the current database
- Search for keywords or phrases found in the Rule Information, Address, or Details columns
- Display rule source content when a user hovers their cursor over a rule match
- Double-click Address column to view associated feature in the Cutter Disassembly view
- Limit tree view results to the function currently displayed in the Cutter Disassembly view; update results as a user navigates to different functions
- Automatically update results when Cutter is used to rename a function
- Select one or more checkboxes to highlight the associated addresses in the Cutter Disassembly view
- Right-click a function match to rename it; the new function name is propagated to Cutter
- Right-click to copy a result by column or by row
- Sort results by column
- Create flags and flagspaces from the loaded matches
- Automatically rename functions with capa matches based on the detected capabilities

![](img/plugin_interface_example_1.png)

## Installation

First locate the directory used by cutter for loading plugins.

The simplest way to do this is to open cutter and go to Edit menu -> Preferences -> Plugins.
The directory you are looking for should be displayed at the top.

Inside that directory you should find a directory named python. Download or clone this repository, and move capa_explorer_plugin to the python directory.

## Usage

Use capa standalone which can be downloaded here

https://github.com/fireeye/capa/releases/

Issue the following command to create a JSON report of the binary.

`capa.exe -j sample.exe > sample.exe.json`

Open the binary in Cutter and and select "Load JSON file" in the drop down menu in the top right corner of the capa explorer widget to load the report.

## Known limitations
- The plugin currently uses r2's ecH command to highlight instructions, while this works the support seems limited in Cutter and at times it can be slow. Ideally BIHighlighter should be used but due to a bug this is currently not exposed in CutterCore. https://github.com/radareorg/cutter/issues/2395
- The main difference between this plugin and the IDA version is that this plugin does not implement a feature extractor and relies on th JSON exports from the IDA plugin or the standalone tool. I have not looked into the possibility of implementing feature extraction with radare2. This may or may not be something I do in the future.  
- The plugin has been developed for Cutter version 1.12 and Ive experienced crashes with earlier versions so make sure to check the version you are running if you are experiencing issues.
- This is my first attempt at a Cutter plugin so there are very likely bugs.
- This plugin does not currently handle rebasing, thats on the todo list.

## Other issues
If you encounter bugs or have suggestions which are not among the known limitations please create an issue, or even better, a pull request.

## Credits
I want to thank FireEye and the FLARE team for creating capa and making it available to everyone. Most of the code in this repo is taken directly from the official capa IDA plugin and and have received slight modifications to make it work in Cutter. The main goal was to make the user experice as close as possible to the original plugin.

https://github.com/fireeye/capa
