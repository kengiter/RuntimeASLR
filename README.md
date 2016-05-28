# RuntimeASLR

RuntimeASLR is a tool to defeat the clone-probing attacks (e.g., [BlindROP][brop]) by re-randomizing
the memory layout of the cloned (i.e., forked) child process at runtime.
RuntimeASLR consists of three components: 
  - policy generator: automatically generates pointer tracking policy; 
  - pointer tracker: accurately tracks all pointers at runtime, guided by the generated tracking policy;
  - rerandomizer: remap all modules to random addresses, update all pointers, and transfer control.

Currently, it only supports x86_64.
RuntimeASLR is built based on Intel's Pin--a dynamic instrumentation tool. Since the 
pointer tracker will be completely detached after re-randomization, RuntimeASLR does not
impose performance overhead to the child process.
We have applied RuntimeASLR to Nginx web server and shown that BlindROP is defeated.

For more details, please refer to the paper: http://www.cc.gatech.edu/~klu38/publications/runtimeaslr-ndss16.pdf
and the web page: https://sslab.gtisc.gatech.edu/pages/memrand.html

Suggestions and comments are welcomed: kjlu@gatech.edu


### Build RuntimeASLR
Easy to build:
```
$ cd <root dir of RuntimeASLR>
$ ./build-all.sh
```

### Run Nginx with RuntimeASLR
```
$ ./run.sh
```
Please have a look at run.sh to see individual steps to use RuntimeASLR.

### Paper
[1] How to Make ASLR Win the Clone Wars: Runtime Re-Randomization, NDSS 2016,
[Kangjie Lu][kangjie], [Stefan Nürnberger][stefan], 
[Michael Backes][michael], and [Wenke Lee][wenke].

```
@inproceedings{lu:runtimeaslr,
  title        = {{How to Make ASLR Win the Clone Wars: Runtime Re-Randomization}},
  author       = {Kangjie Lu and Stefan N{\"u}rnberger and Michael Backes and Wenke Lee},
  booktitle    = {Proceedings of the 2016 Annual Network and Distributed System Security Symposium (NDSS)},
  month        = Feb,
  year         = 2016,
  address      = {San Diego, CA},
}
```

[kangjie]:  <http://www.cc.gatech.edu/~klu38/>
[stefan]:   <https://www.infsec.cs.uni-saarland.de/~nuernberger/>
[michael]:  <https://www.infsec.cs.uni-saarland.de/~backes/>
[wenke]:    <http://wenke.gtisc.gatech.edu/>
[brop]:			<http://www.scs.stanford.edu/brop/>
