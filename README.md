# ThreatRaptor

Given a natural language description of an attack behavior, the ThreatRaptor system automatically searches for the matched system audit log records for cyber threat hunting.

Specifically, the system (1) extracts attack behaviors from the description using NLP techniques; (2) synthesizes a threat hunting query (a TBQL query) from the extracted behaviors; (3) executes the synthesized query over the database of system audit logs for threat hunting.

If you use or extend our work, please cite the following ICDE 2021 paper:

```txt
@inproceedings {gao2021enabling,
 title = {Enabling Efficient Cyber Threat Hunting With Cyber Threat Intelligence},
 author={Gao, Peng and Shao, Fei and Liu, Xiaoyuan and Xiao, Xusheng and Qin, Zheng and Xu, Fengyuan and Mittal, Prateek and Kulkarni, Sanjeev R and Song, Dawn},
 booktitle = {2021 IEEE 37th International Conference on Data Engineering (ICDE)},
 year = {2021},
 pages = {193-204},
 doi = {10.1109/ICDE51399.2021.00024},
 url = {https://doi.ieeecomputersociety.org/10.1109/ICDE51399.2021.00024},
}
```

## How to install

### 1. Install st2g

Install from [here](https://github.com/peng-gao-lab/st2g)

### 2. Build ANTLR 4 parser files

Tested using Antlr 4.7.1 for MacOS

#### ANTLR 4 configuration notes

`antlr` script in `/usr/local/bin/`:

```bash
#!/bin/bash
java -cp "/usr/local/lib/antlr4-4.7.1-complete.jar:$CLASSPATH" org.antlr.v4.Tool $*
```

`grun` script in `/usr/local/bin/`:

```bash
#!/bin/bash
java -cp "/usr/local/lib/antlr4-4.7.1-complete.jar:$CLASSPATH" org.antlr.v4.runtime.misc.TestRig $*
```

#### ANTLR 4 running notes

Generate java files:

```bash
cd src/grammar
./build_tbql.sh # we used antlr 4.7.1 to generate parser files
```

### 3. Optional: Build UI

Build JS files

```bash
# Under the /frontent directory
npm install
npm run build
```

### 4. Optional: Prepare the database

The TBQL query needs to run on a database of system audit logging records. ThreatRaptor supports both PostgreSQL database and Neo4j database.

Example database to try: `input/example/logsanalyzer_2019_10_06.sql`.

To generate an system audit log file using Sysdig (tested for version 0.26.4), execute the following command:

```bash
sudo sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency exepath=%proc.exepath cmd= %proc.exeline"  "proc.name!=tmux and (evt.type=read or evt.type=readv or evt.type=write or evt.type=writev or evt.type=fcntl or evt.type=accept or evt.type=execve or evt.type=clone or evt.type=pipe or evt.type=rename or evt.type=sendmsg or evt.type=recvmsg) and proc.name!=sysdig"
```

The log then needs to be parsed to populate the database, with the same schema as `input/example/logsanalyzer_2019_10_06.sql`.

## How to run

* Create database for system audit logging data (can try example database `input/example/logsanalyzer_2019_10_06.sql`)

* Configure `cfg/database/*.properties`

### Run the TBQL query component only

* Run `Main.java -> runBQL()` (this executes the query `input\example\tbql_sql.tbql` by default)

Depending on the type of event pattern/event path, the query system will interact with the PostgreSQL database or the Neo4j database for fetching the results.

`input\example` gives several other example TBQL queries that ThreatRaptor supports. For queries with the variable length path syntax, the Neo4j database needs to be set up.

### Run the end-to-end pipeline

* Run `Main.java -> runPipeline()`

The system will take in a natural language attack behavior description as an input (e.g., `input/example/attack_description.txt`), construct an attack behavior graph in DOT format, synthesize a TBQL query from the graph, and execute the query to find the matched system audit logging records.

### Run the UI

* Run `Main.java -> runWeb()`
* UI is at `localhost:8080`

## A demo case

Natural language description of attak behavior (`input/example/attack_description.txt`):

```txt
First, /usr/bin/wget will be started by /bin/bash . It downloads some data from 162.125.6.6, then writes the data to sysrep_exp_data.txt.
```

Constructed attack behavior graph in DOT format:

```txt
digraph {
 0 [label="/usr/bin/wget" xlabel=LinuxFilepath]
 1 [label="/bin/bash" xlabel=LinuxFilepath]
 2 [label="162.125.6.6" xlabel=IP]
 3 [label="sysrep_exp_data.txt" xlabel=Filename]
 1 -> 0 [label=start xlabel="[0]"]
 0 -> 2 [label=download xlabel="[1]"]
 0 -> 3 [label=write xlabel="[2]"]
}
```

Synthesized TBQL query (can configure `SecurityOperationGraph.java` for different synthesis options)

```txt
proc p1['%/bin/bash%'] start proc p2['%/usr/bin/wget%'] as evt1
proc p2['%/usr/bin/wget%'] read ip i1['162.125.6.6'] as evt2
proc p2['%/usr/bin/wget%'] write file f1['%sysrep_exp_data.txt%'] as evt3
with evt1 before evt2, evt2 before evt3
return distinct p1, p2, i1, f1
```

Retrieved system audit logging records from database `input/example/logsanalyzer_2019_10_06.sql`:

```txt
/bin/bash, /usr/bin/wget, 162.125.6.6, /home/pxf109/Reptracker/sysrep_case_scripts/complex_case/complex_case/sysrep_exp_data.txt?dl=0
[p1.exename, p2.exename, i1.dstip, f1.name]

```

Screenshot of UI: `ui_demo.png`
