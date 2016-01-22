module libackis.ackiscomponent;

import std.socket;
debug(libackis)import std.stdio : writefln,writef;
import std.string;
import std.random;
version(D_Version2) {
	import core.thread: Thread;
	import std.conv: to;
	string tostring(int data) {
		return to!(string)(data);
	}
	import std.regex;
	import std.parallelism:TaskPool,task,taskPool;
	string md5StringOf(string input) {
		import std.digest.md:md5Of,toHexString;
		ubyte[16]hash = md5Of(input);
		return toHexString(hash).idup;
	}
	import core.stdc.errno:errno,EINTR,EAGAIN;
	int getErrno() {
		return errno;
	}
        import core.time:dur;
} else {
	import std.thread: Thread;
	import std.c.stdlib: getErrno;
	alias toString tostring;
	import std.regexp;
	import tools.threadpool;
	import tools.base;
	import std.md5:sum,digestToString;
	string md5StringOf(string input) {
	        ubyte[16]digest;
		sum(digest,input);
		return digestToString(digest);
	}
}
import object;
import kxml.xml;

// XXX make this struct so that it can hold multiple event/attributes groupings XXX
struct XmlPacket {
	// response ID for events
	string respid;
	// this is the event, one of: message, register, variable, resource
	string event;
	// this AA holds all of the inner attributes
	string[string]attributes;
}

class AckisComponent {
	private {
		string buffer;
		Socket connection;
		// this is to help the GC remember that the socket hasn't been dereferenced....
		string username;
		string password;
		// for callbacks, the first string is always the response ID, the other string(s) may vary
		// the arguments other than "this" are the responseid, the message type, and the data, in that order
		void function(AckisComponent,string,string,string)[string]callbacks;
		// this holds the descriptions for the implied triggered help callback
		string[string]descriptions;
		// the arguments other than "this" are the responseid from the packet tag, the variable name, and the response id from the original message in that order
		void function(AckisComponent,string,string,string)varcb;
		// response callback, there is always the possibility of multiple responses or no responses
		// so this can't work like the variable transactions do
		// second string is the data response
		void function(AckisComponent,string,string,string)responsecb;
		void function(AckisComponent,string)errorcb;
		string componentType;
		string modname;
		string coreAddress;
		ushort listenport;
		// use Object for locks
		Object varlock;
		Thread runthread;
		bool running;
		bool registered;
		// variable array for received variables
		string[string][string]varray;
		// list for response ids of sent variable requests
		// AA for ease of use and laziness
		bool[string]varespid;
		version(D_Version2) {
		} else {
			Threadpool threadpool;
		}

		static void callback_shim(void function(AckisComponent,string,string,string) callback,
			AckisComponent ackis, string s1, string s2, string s3) {
			try {
				callback(ackis, s1, s2, s3);
			} catch (Exception e) {
				debug(libackis)writefln("Caught exception from callback: %s", e.msg);
			}
		}
	}
	this (string mname="default_name",string comptype = "module",string address = "127.0.0.1",ushort port = 16668,string user=null,string pass=null) {
		// make sure components running the old syntax barf hard
		if (mname == "module" || mname == "resource" || mname == "client") throw new Exception("AckisComponent: You're using '"~mname~"' as your component name. Perhaps you haven't upgraded your constructor call.");
		modname = mname;
		componentType = comptype;
		listenport = port;
		coreAddress = address;
		varlock = new Object;
		running = false;
		registered = false;
		username = user;
		password = pass;
		version(D_Version2) {
		} else {
			threadpool = new Threadpool(30);
		}
		// resources don't register a typical help callback
		// so only register if not a resource
		if (comptype.icmp("resource") != 0) {
			register("^help.*",&helpcb);
		}
	}

	void setAuthCreds(string user,string pass) {
		username = user;
		password = pass;
	}
	// 0 on success, 1 on failure
	int sendMessage (string responseid,string message,string messagetype = null) {
		XmlPacket packet;
		packet.respid = responseid;
		packet.event = "message";
		packet.attributes["data"] = message;
		packet.attributes["mime"] = "text/plain";
		packet.attributes["type"] = messagetype;

		if (running) {
			sendPacket(packet);
			return 0;
		} else {
			return 1;
		}
	}

	int sendResponse (string responseid,string response,string responsetype = null) {
		if (componentType.icmp("resource") != 0) {
			return sendMessage(responseid,response,responsetype);
		}
		// we have a resource to deal with
		// format is respid, data, type
		XmlPacket packet;
		packet.respid = responseid;
		packet.event = componentType;
		packet.attributes["type"] = responsetype;
		packet.attributes["data"] = response;

		if (running) {
			sendPacket(packet);
			return 0;
		} else {
			return 1;
		}
	}

	int sendAuth(string responseid,string username,string hash) {
		XmlPacket packet;
		packet.respid = responseid;
		packet.event = "auth";
		packet.attributes["username"] = username;
		packet.attributes["hash"] = hash;

		if (running) {
			sendPacket(packet);
			return 0;
		}
		return 1;
	}

	string getVariable (string responseid,string varname) {
		XmlPacket packet;
		packet.attributes["responseid"] = responseid;
		// make the new outgoing respid random so we don't have collisions on variable requests
		version(D_Version2) {
			import std.random:uniform;
			responseid = "var"~tostring(uniform!int());
		} else {
			responseid = "var"~tostring(rand());
		}
		packet.respid = responseid;
		packet.event = "variable";
		packet.attributes["name"] = varname;

		varespid[responseid] = true;

		if (running) {
			sendPacket(packet);
			if (waitVar(responseid,varname)) {
				synchronized (varlock) {
					string tmp = varray[responseid][varname];
					varray[responseid].remove(varname);
					return tmp;
				}
			}
		}
		return null;
	}

	// this should probably be an int to say whether we got the var or not
	private int waitVar(string respid,string varname) {
		// timeout is currently 5 seconds for a variable request
		int timeout = 500;
		debug(libackis)writefln("Waiting for variable %s",varname);
		int x;
		for(x = 0;x<timeout;x++) {
			synchronized (varlock) {
				// check to see if it exists
				if ((respid in varray) != null) {
					if ((varname in varray[respid]) != null) {
						debug(libackis)writefln("found %s in varray!",respid);
						return 1;
					} else {
						debug(libackis)writef(".");
					}
				}
			}
			// yeah, shut up, i'm using this as microsleep (usleep)
			Socket.select(null,null,null,dur!"msecs"(10));
		}
		debug(libackis){
			if (x == timeout) {
				writefln("Variable not received!");
			} else {
				writefln("Got variable %s",varname);
			}
		}
		return 0;
	}

	private string genResponseID(string input) {
		return md5StringOf(input);
	}


	// basically rip the code from getvariable and use the same wait function as well as the AA used for variables
	// bear in mind that resources can't query other resources or modules or clients
	string queryResource (string resource,string action,string data=null) {
		XmlPacket packet;
		packet.event = "resource";
		packet.attributes["type"] = resource;
		packet.attributes["action"] = action;
		if (data.length) {
			packet.attributes["data"] = data;
		}
		// generate a new responseid from the query since we hope it's a good source of entropy
		packet.respid = genResponseID(resource~action);
		varespid[packet.respid] = true;

		if (running) {
			sendPacket(packet);
			if (waitVar(packet.respid,resource)) {
				synchronized (varlock) {
					// save the var and remove it from "public" view
					string tmp = varray[packet.respid][resource];
					varray[packet.respid].remove(resource);
					return tmp;
				}
			}
		}
		return null;
	}

	// throws an exception on failure
	void Connect() {
		if (runthread is null) {
			version(D_Version2) {
				runthread = new Thread(&vrunProtocol);
			} else {
				runthread = new Thread(&runProtocol);
			}
			runthread.start();
			// make sure thread execution actually starts...i was having issues with this
			// b/c the thread takes time to spool up for one reason or an other
			while (!running){
				Socket.select(null,null,null,dur!"msecs"(1));
			}
		}
	}

	void wait() {
		if (runthread !is null) {
			version(D_Version2) {
				runthread.join();
			} else {
				runthread.wait();
			}
		}
	}
	// register all of our callbacks with the core we're connecting to
	private void doRegistrations () {
		int respid = 8675309;
		XmlPacket reg;
		reg.event = "register";
		reg.attributes["type"] = componentType;
		reg.attributes["callback"] = null;
		reg.attributes["mime"] = "text/plain";
		if (!callbacks.length) {
			debug(libackis)writefln("Sending blank registration");
			sendPacket(reg);
		} else foreach (key;callbacks.keys) {
			debug(libackis)writefln("Sending registration for callback: %s",key);
			reg.respid = "regpack"~tostring(respid);
			respid++;
			reg.attributes["callback"] = key;
			sendPacket(reg);
		}
	}
	void vrunProtocol() {
		runProtocol();
	}
	int runProtocol () {
		for(int x = 0;x<100;x++) { // i didn't realize how ugly this could be
			handleSocket();
			// wait 10 seconds between connection attempts, will probably be longer considering time for overhead
			Socket.select(null,null,null,dur!"seconds"(10));
		}
		// die after 100 attempts
		return 1;
	}

	private int handleSocket() {
		connection = new TcpSocket(new InternetAddress(coreAddress,listenport));
		assert(connection.isAlive);
		connection.blocking = false;

		debug(libackis)writefln("Connected to localhost on port %d.", cast(int)listenport);
		running = true;
	
		SocketSet sset = new SocketSet();
		
		while(true) {
			sset.add(connection);
			Socket.select(sset, null, null);
			debug(libackis)writefln("Processing event...");
			if (sset.isSet(connection)) {
				char[1024] buf;
				ptrdiff_t read;
				synchronized (connection) read = connection.receive(buf);
				if (read != Socket.ERROR && read > 0) {
					buffer ~= buf[0 .. read];
					// make sure we get ALL the data before attempting a parse
					if (read == 1024) {
						SocketSet single = new SocketSet();
						single.add(connection);
						// using socket.select to figure out whether there is data available is really annoying
						while (Socket.select(single,null,null) > 0) {
							synchronized (connection) read = connection.receive(buf);
							buffer ~= buf[0 .. read];
							single.add(connection);
							debug(libackis)writefln("Reading more parts of the packet!");
						}
					}
					handleXML();
				} else if (read == Socket.ERROR || read == 0) {
					//version(Windows) { } else { if (getErrno==4) { debug(libackis)writefln("EINTR encountered!"); continue; }}
					if (getErrno==EINTR || getErrno==EAGAIN) {
						debug(libackis)writefln("EINTR or EAGAIN encountered!");
						continue;
					}
					debug(libackis)writefln("Connection Lost! Errno = %d",getErrno);
					// release socket resources
					if (connection !is null) synchronized (connection) connection.close();
					// remove buffer
					buffer = null;
					// die
					connection = null;
					break;
				}
			} else {
				// if we hit this, it means that for some reason, we're not picking up the socket error and we need to just die
				break;
			}
		}
		return 1;
	}
	
	
	// this function tries to determine if there is a viable xml packet available in a text string
	// if there is, it returns a 1, a XmlPacket structure with data in it, and a modifed string
	private int handleXML() {
		XmlNode xml;
		string tmp = null;
		try {
			xml = readDocument(buffer);
			debug(libackis)writefln("%s",xml.toString());
			// since it always comes back with a blank root node, we need to get the first child that's packet
			foreach (child;xml.parseXPath("packet")) {
				XmlPacket packet;
				if (nodeToPacket(child,packet)) try {
					handlePacket(packet);
				} catch(Exception e) {
					debug(libackis)writefln("Failed to parse packet: %s", child.toString());
					debug(libackis)writefln("Got exception: %s", e.msg);
				}
				xml.removeChild(child);
			}
			buffer = null;
			// no reason to keep the junk
			foreach (child;xml.getChildren) {
				debug(libackis)writefln("Not a packet tag: %s",child.toString());
			}
		} catch (Exception e) {
			debug(libackis)writefln("%s",e.toString());
			// return code for failure
			return 0; 
		}
		
		return 1;
	}
	
	private int nodeToPacket(XmlNode xml,ref XmlPacket packet) {
		foreach (string key,string value;xml.getAttributes()) {
			// look for a responseid attribute
			if (key.icmp("responseid") == 0) {
				packet.respid = value;
			}
		}
		packet.event = null;
		// the getname could be replaced with a xpath or operation
		foreach (XmlNode child;xml.getChildren()) if (!child.isCData()) {
				packet.event = child.getName();
				// make sure that the element has a data attribute
				packet.attributes = child.getAttributes;
				// we currently only support one event per packet, this will change in the future and requires minimal changes
				break;
		}
		// do our best to verify that this packet is somewhat valid
		if (packet.event.length && isValidEvent(packet.event)) {
			return 1;
		}
		return 0;
	}

	private string[]eventlist = ["message","resource","variable","auth","error","info","register","component"];
	private bool isValidEvent(string event) {
		// this can be done dynamically with an array/foreach, might be better that way
		// we don't need to ever check for authreply here because we'll never be receiving one
		foreach(item;eventlist) {
			if (event.icmp(item) == 0) return 1;
		}
		return 0;
	}
	
	private XmlNode packetToNode(XmlPacket packet) {
		XmlNode xpacket = new XmlNode("packet");

		xpacket.setAttribute("responseid",packet.respid);
		// this needs to be modified to support multipackets
		XmlNode element = new XmlNode(packet.event);
		foreach(key,value;packet.attributes) {
			element.setAttribute(key,value);
		}
		xpacket.addChild(element);
		return xpacket;
	}
	

	private void handlePacket(XmlPacket packet) {
		// so right now, I'm just going to print the packet contents
		debug(libackis)writefln("Got good packet: event(%s),responseid(%s)\n",packet.event,packet.respid);
		// if we have an incoming variable packet, it means that a request has probably been fullfilled and we should add it to the list
		if (packet.event.icmp("variable") == 0) {
			if ((packet.respid in varespid) !is null) {
				debug(libackis)writefln("Received a variable response! with respid %s, and name:data %s:%s",packet.respid,packet.attributes["name"],packet.attributes["value"]);
				// this is a response to a variable request we sent
				// make sure to sync on the varlock object
				synchronized (varlock) {
					varray[packet.respid][packet.attributes["name"]] = packet.attributes["value"];
				}
				// we're done here
			} else {
				// this is a request for a variable by someone else
				debug(libackis)writefln("Received a request for a variable!");
				if (varcb != null) {
					version(D_Version2) {
						taskPool.put(task(varcb, this, packet.respid.idup, packet.attributes["name"].idup, packet.attributes["responseid"].idup));
					} else {
						threadpool.future(varcb /fix/ stuple(this, packet.respid.dup, packet.attributes["name"].dup, packet.attributes["responseid"].dup));
					}
				}
				// done here, too
			}
			return;
		}
		if (packet.event.icmp("info") == 0) {
			string num = packet.attributes["number"];
			if (num == "403") {
				debug(libackis)writefln("Received a request for authentication!");
				string tmp = username~packet.respid~password;
				// that last one needs to be the hash of tmp
				sendAuth(packet.respid,username,md5StringOf(tmp));
				return;
			} else if (num == "200") {
				if (!registered) {
					// we're not registered yet, so register
					registered = true;
					doRegistrations();
				}
				return;
			} else {
				// for anything else, we want to throw an error
				errorcb(this,"Error "~num~": "~packet.attributes["message"]);
			}
		}
		if (packet.event.icmp("component") == 0) {
			if (packet.attributes["action"] == "get" && packet.attributes["type"] == "name") {
				// return our data in an info frame with num 200
				// rewrite the packet we have because we can
				debug(libackis)writefln("got request for name, sending %s",modname);
				packet.attributes.remove("action");
				packet.attributes.remove("type");
				packet.event = "info";
				packet.attributes["number"] = "200";
				packet.attributes["message"] = modname;
				sendPacket(packet);
			}
			return;
		}
		if (packet.event.icmp("message") == 0) {
			// since we've gotten this far and we seem to have a good packet, rummage through our regexen to see what to do
			// iterate through the callbacks looking for matches, and send to ALL matching functions
			bool caughtcb = false;
			foreach (string regex;callbacks.keys) {
				bool found = false;

				regrep(packet.attributes["data"], regex, (string m){
					found = true;
					return m;
				});

				if (found) {
					debug(libackis)writefln("Pushing execution into task for %s",regex);
					string type = "";
					version(D_Version2) {
						if ("type" in packet.attributes) {
							type = packet.attributes["type"].idup;
						}
						taskPool.put(task(&callback_shim, callbacks[regex], this, packet.respid.idup, packet.attributes["data"].idup, type));
					} else {
						if ("type" in packet.attributes) {
							type = packet.attributes["type"].dup;
						}
						threadpool.future(&callback_shim /fix/ stuple(callbacks[regex], this, packet.respid.dup, packet.attributes["data"].dup, type));
					}
					debug(libackis)writefln("Spawned task for %s",regex);
					caughtcb = true;
				}
			}
			if (!caughtcb && responsecb != null) {
				// i guess this is a response, since we didn't match a callback
				debug(libackis)writefln("Got a response to a previously sent message...");
				version(D_Version2) {
					taskPool.put(task(responsecb, this, packet.respid.idup, packet.attributes["data"].idup, packet.attributes["type"].idup));
				} else {
					threadpool.future(responsecb /fix/ stuple(this, packet.respid.dup, packet.attributes["data"].dup, packet.attributes["type"].dup));
				}
			}
			return;
		}
		// this is a hybrid of the variable and message types
		if (packet.event.icmp("resource") == 0) {
			if ((packet.respid in varespid) !is null || componentType.icmp("resource") != 0) {
				debug(libackis)writefln("Received a resource response! with respid %s, and type:data %s:%s",
					packet.respid,packet.attributes["type"],packet.attributes["data"]);
				// this is a response to a resource query we sent
				// make sure to sync on the varlock object
				synchronized (varlock) {
					varray[packet.respid][packet.attributes["type"]] = packet.attributes["data"];
				}
				// we're done here
			} else if (componentType.icmp("resource") == 0) {
				// this is a query for a resource by someone else
				debug(libackis)writefln("Received a resource query!");
				foreach (string regex;callbacks.keys) {
					bool found = false;

					regrep(packet.attributes["type"], regex, (string m){
						found = true;
						return m;
					});

					if (found) {
						debug(libackis)writefln("Calling function for %s",regex);
						version(D_Version2) {
							taskPool.put(task(&callback_shim, callbacks[regex], this, packet.respid.idup, packet.attributes["action"].idup, packet.attributes["type"].idup));
						} else {
							threadpool.future(&callback_shim /fix/ stuple(callbacks[regex], this, packet.respid.dup, packet.attributes["action"].dup, packet.attributes["type"].dup));
						}
						// if we matched, we're done since we only want to match once
						return;
					}
				}
				// done here, too
			}
			return;
		}
	}
	
	void setVariableCB(void function(AckisComponent,string,string,string)variablecb) {
		varcb = variablecb;
	}

	void setResponseCB(void function(AckisComponent,string,string,string)respcb) {
		responsecb = respcb;
	}

	void setErrorCB(void function(AckisComponent,string)errcb) {
		errorcb = errcb;
	}

	int sendVariable (string responseid,string varname,string varval) {
		// build a variable packet
		XmlPacket packet;
		packet.event = "variable";
		packet.respid = responseid;
		packet.attributes["name"] = varname;
		packet.attributes["value"] = varval;

		if (running) {
			sendPacket(packet);
			return 0;
		}
		return 1;
	}

	void register(string regex,void function(AckisComponent,string,string,string)callbackdg) {
		callbacks[regex] = callbackdg;
		if (registered) {
			static int respid = 0;
			XmlPacket reg;
			reg.event = "register";
			reg.attributes["type"] = componentType;
			reg.attributes["callback"] = regex;
			reg.attributes["mime"] = "text/plain";
			reg.respid = "pcreg"~tostring(respid);
			respid++;
			debug(libackis)writefln("Sending registration for callback: %s",regex);
			sendPacket(reg);
		}
	}

	void regHelp(string trig,string desc) {
		descriptions[trig] = desc;
	}
	
	void sendPacket(XmlPacket msg) {
		debug(libackis)writefln("Sending packet: %s",packetToNode(msg).toString());
		if (connection is null) {
			debug(libackis)writefln("TRIED TO SEND PACKET WITH NULL CONNECTION!\nSOMETHING IS BROKEN");
		} else {
			synchronized (connection) connection.send(packetToNode(msg).toString());
		}
	}

	private static void helpcb(AckisComponent ackis,string respid,string data,string type) {
		if (type.icmp("triggered") != 0) {
			return;
		}
		data = data["help".length..$];
		if (data.length > 1) {
			// look to see if we have this in the array
			if ((data[1..$] in ackis.descriptions) !is null) {
				ackis.sendResponse(respid,ackis.descriptions[data[1..$]]);
			}
		} else {
			auto chat = ackis.getVariable(respid,"chat");
			auto user = ackis.getVariable(respid,"user");
			if (!chat || !chat.length || !user || !user.length || chat == user) {
				/* only provide a listing of help information in private message */
				ackis.sendResponse(respid,ackis.modname~" triggers: "~ackis.descriptions.keys.join(", "));
			}
		}
	}
}
