# capa-explorer for Cutter
capa explorer for Cutter.

## Installation

## Usage

`capa.exe -j sample.exe > sample.exe.json`

## Known limitations
- The plugin currently uses r2's ecH command to highlight instructions, while this works the support seems limited in Cutter and at times it can be slow. Ideally BIHighlighter should be used but due to a bug this is currently not exposed in CutterCore. https://github.com/radareorg/cutter/issues/2395
- The main difference between this plugin and the IDA version is that this plugin does not implement a feature extractor and relies on th JSON exports from the IDA plugin or the standalone tool. I have not looked into the possibility of implementing feature extraction with radare2. This may or may not be something I do in the future.  



## Credits
Big thanks to FireEye ant the FLARE team for creating this tool and making it availible to everyone. Most of the code in this repo is taken directly from the official capa IDA plugin and and have received slight modifications to make it work in Cutter.

https://github.com/fireeye/capa

Also a big thanks to the creators of radare2 and Cutter.

https://github.com/radareorg/cutter
