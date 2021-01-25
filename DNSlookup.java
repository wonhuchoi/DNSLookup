import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Random;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.UnknownHostException;

public class DNSlookup {
    
	static final int MAX_TTL_COUNT = 30;
	static final int DNS_PORT = 53;
    static final int SECONDS_BEFORE_RESEND = 5;
    static final int MIN_PERMITTED_ARGUMENT_COUNT = 2;
    static final int MAX_PERMITTED_ARGUMENT_COUNT = 3;
	static int ttl = 0;
	static boolean tracingOn = false;
	static boolean IPV6Query = false;
	
	/**
     * @param args
     */
    public static void main(String[] args) throws Exception {
		String fqdn;
		DNSResponse response; // Just to force compilation
		int argCount = args.length;
		InetAddress rootNameServer;
		InetAddress NameServer;
		
		if (argCount < MIN_PERMITTED_ARGUMENT_COUNT || argCount > MAX_PERMITTED_ARGUMENT_COUNT) {
			usage();
			return;
		}
		fqdn = args[1];
		String original_fqdn = fqdn;
		try {
			NameServer = InetAddress.getByName(args[0]);
			rootNameServer = InetAddress.getByName(args[0]);
			
			if (argCount == 3) {  // option provided
				if (args[2].equals("-t"))
					tracingOn = true;
				else if (args[2].equals("-6"))
					IPV6Query = true;
				else if (args[2].equals("-t6")) {
					tracingOn = true;
					IPV6Query = true;
				} else  { // option present but wasn't valid option
					usage();
					return;
				}
			}
			
			if(IPV6Query) {
				while (ttl < DNSlookup.MAX_TTL_COUNT) {
					response = PerformIPQuery(fqdn, NameServer, true);
					if (response != null) {
						String CN = checkforCN(response, fqdn);
						printResponseTrace(response, NameServer, fqdn);
						if (CN != null) {
							// Set for the CName.
							fqdn = CN;
							NameServer = rootNameServer;
						} else if (handleResponseV6(response)) {
							standardOutputV6(response, original_fqdn);
							return;
						} else {
							// Get new NameServer
							NameServer = getNextServer(response, fqdn, true, rootNameServer);
							if(NameServer == null) {
								returnError(fqdn, true, "-4");
							}
						}
					} else {
						returnError(fqdn, true, "-4");
					}
				}
				returnError(fqdn, true, "-3");
			} else {
				while (ttl < DNSlookup.MAX_TTL_COUNT) {
					response = PerformIPQuery(fqdn, NameServer, false);
					if (response != null) {
						String CN = checkforCN(response, fqdn);
						printResponseTrace(response, NameServer, fqdn);
						if (CN != null) {
							// Set for the CName.
							fqdn = CN;
							NameServer = rootNameServer;
						} else if (handleResponseV4(response)) {
							standardOutputV4(response, original_fqdn);
							return;
						} else {
							// Get new NameServer
							NameServer = getNextServer(response, fqdn, false, rootNameServer);
							if(NameServer == null) {
								returnError(fqdn, false, "-4");
							}
						}
					} else {
						returnError(fqdn, false, "-4");
					}
				}
				returnError(fqdn, false, "-3");
			}
		} catch (UnknownHostException e) {
			returnError(fqdn, IPV6Query, "-4");
		}
    }

	private static InetAddress lookupNSAddress(String fqdn, InetAddress NameServer) {
		InetAddress rootNameServer = NameServer;
		try {
			while (ttl < DNSlookup.MAX_TTL_COUNT) {
				DNSResponse response = PerformIPQuery(fqdn, NameServer, false);
				if (response != null) {
					if (handleResponseV4(response)) {
						for (DNSAnswer answer: response.getAnswers()) {
							if (answer.getType() == 1) {
								return InetAddress.getByName(answer.getData());
							}
						}
					} else {
						//Get new NameServer
						NameServer = getNextServer(response, fqdn, false, rootNameServer);
						if(NameServer == null) {
							returnError(fqdn, false, "-4");
						}
					}
				} else {
					returnError(fqdn, false, "-4");
				}
			}
			returnError(fqdn, false, "-3");
		} catch (UnknownHostException e) {
			returnError(fqdn, false, "-4");
		}
		return null;
	}

	// Returns proper output format.
	private static void standardOutputV4(DNSResponse response, String fqdn) {
		for (DNSAnswer answer: response.getAnswers()) {
			if(answer.getType() == 1) {
				System.out.println(fqdn + " "  + answer.getTTL() + "   " + "A" + " "  + answer.getData());
			}
		}
	}

	private static void standardOutputV6(DNSResponse response, String fqdn) { 
		for (DNSAnswer answer: response.getAnswers()) {
			if(answer.getType() == 28) {
				System.out.println(fqdn + " "  + answer.getTTL() + "   " + "AAAA" + " "  + truncate(answer.getData()));
			}
		}
	}

	// Gets rid of leading zeros to output nicely for IPv6.
	private static String truncate(String address) {
		boolean remove = true;
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < address.length()-1; i++) {
			if (address.charAt(i) == ':') {
				remove = true;
				sb.append(':');
			} else if (address.charAt(i) != '0') {
				remove = false;
				sb.append(address.charAt(i));
			} else if (address.charAt(i) == '0') {
				if (address.charAt(i+1) != ':' && remove) {
				// Don't add this 0
				} else {
					sb.append('0');
				}
			}
		}
		sb.append(address.charAt(address.length()-1));
		return sb.toString();
	}

	// Print error message and return
	private static void returnError(String fqdn, boolean v6, String errorCode) {
		String type = "A";
		String def = " 0.0.0.0";
		if (v6) {
			type = "AAAA";
		}
		System.out.println(fqdn + " " + errorCode + "   " + type + def);
		System.exit(1);
	}
	
	private static DNSResponse PerformIPQuery(String fqdn, InetAddress IPAddress, boolean v6) {
		try{
			DatagramSocket clientSocket = new DatagramSocket();
			byte[] receiveData = new byte[1024];
			int queryID = getNewQueryID();
			byte[] sendData = constructIPQuery(fqdn, queryID, (v6) ? 28 : 1);
			boolean hasBeenResent = false;
			while(true) {
				if(++ttl > DNSlookup.MAX_TTL_COUNT) {
					returnError(fqdn, v6, "-3");
				}
				try{
					DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, DNS_PORT);
					clientSocket.setSoTimeout(SECONDS_BEFORE_RESEND * 1000);
					clientSocket.send(sendPacket);
					DatagramPacket DatagramPacketRecievePacket = new DatagramPacket(receiveData, receiveData.length);
					clientSocket.receive(DatagramPacketRecievePacket);
					DNSResponse response = new DNSResponse(receiveData, receiveData.length);
					if (response.getQueryID() != queryID) {
						returnError(fqdn, v6, "-4");
					}
					checkRcode(response, fqdn, v6);
					return response;
				} catch (SocketTimeoutException e) {
					if(hasBeenResent == false){
						hasBeenResent = true;
					} else {
						// return DNS response with TTL = -2
						returnError(fqdn, v6, "-2");
						break;
					}
				} catch (IOException e) {
					returnError(fqdn, v6, "-4");
					break;
				}
			}
		} catch (SocketException e) {
			returnError(fqdn, v6, "-4");
		} catch (Exception e) {
			returnError(fqdn, v6, "-4");
		}
		// stub returns null
		return null;
	}

	private static void printResponseTrace(DNSResponse response, InetAddress NameServer, String fqdn) {
		String type = "A";
		if (IPV6Query)
			type = "AAAA";
		if (tracingOn) {
			System.out.println("\n\n");
			System.out.println("Query ID     " + response.getQueryID() + " " + fqdn + "  " + type + " --> " + inetToString(NameServer));
			System.out.println("Response ID: " + response.getQueryID() + " Authoritative = " + response.isAuthoritative());
			System.out.println("  Answers (" + response.getAnswersCount() + ")");
			for (DNSAnswer a : response.getAnswers()) {
				System.out.println("       " + String.format("%1$-" + 30 + "s", a.getName()) + " " + String.format("%1$-" + 10 + "s", a.getTTL()) + " " + String.format("%1$-" + 4 + "s", getRecordTypeByInt(a.getType())) + " " + a.getData());
			}
			System.out.println("  Nameservers (" + response.getNSCount() + ")");
			for (NSRecord r : response.getNSRecords()) {
				System.out.println("       " + String.format("%1$-" + 30 + "s", r.getName()) + " " + String.format("%1$-" + 10 + "s", r.getTTL()) + " " + String.format("%1$-" + 4 + "s", getRecordTypeByInt(r.getType())) + " " + r.getData());
			}
			System.out.println("  Additional Information (" + response.getAdditionalInfoCount() + ")");
			for (AdditionalEntry a : response.getAdditional()) {
				System.out.println("       " + String.format("%1$-" + 30 + "s", a.getName()) + " " + String.format("%1$-" + 10 + "s", a.getTTL()) + " " + String.format("%1$-" + 4 + "s", getRecordTypeByInt(a.getType())) + " " + a.getData());
			}
		}
	}

	private static String getRecordTypeByInt(int type) {
		switch (type) {
			case 1:
				return "A";
			case 2:
				return "NS";
			case 5:
				return "CN";
			case 28:
				return "AAAA";
			default:
				return (new Integer(type)).toString();
		}
	}

	private static String inetToString(InetAddress address) {
		return address.toString().substring(1);
	}

	private static byte[] constructIPQuery(String fqdn, int queryID, int type) {
		try {
			// Declare values to be inserted into the query
			ByteArrayOutputStream byteArrayOS = new ByteArrayOutputStream();
			DataOutputStream dataOS = new DataOutputStream(byteArrayOS);
			int QueryID = queryID;
			int QDCount = 1;
			int ANCount = 0;
			int NSCount = 0;
			int ARCount = 0;
			String[] Name = fqdn.split("\\.");
			int Type = type; // Query type 1 or 28
			int Class = 1; // ClassType IN
			// Instansiate ByteBuffer and add all the elements
			dataOS.writeShort(QueryID);
			// Writing all the flags (all of which are 0)
			dataOS.writeShort(0x0000);
			// Writing number of queries
			dataOS.writeShort(QDCount);
			// Writing number of answers
			dataOS.writeShort(ANCount);
			// Writing NSCount
			dataOS.writeShort(NSCount);
			// Writing NSCount
			dataOS.writeShort(ARCount);
			// Writing each part of the domain name
			for (int i = 0; i < Name.length; ++i) {
				dataOS.writeByte(Name[i].length());
				byte[] domainPartByteStream = Name[i].getBytes();
				dataOS.write(domainPartByteStream);
			}
			// Writing 0x00 to indicate no more parts
			dataOS.writeByte(0x00);
			// Writing 0x00 to indicate no more parts
			dataOS.writeShort(Type);
			// Writing 0x00 to indicate no more parts
			dataOS.writeShort(Class);
			return byteArrayOS.toByteArray();
		} catch (IOException e) {
			System.out.print("IOException: " + e.getMessage());
			return new byte[0];
		}
	}

	private static int getNewQueryID() {
		return new Random().nextInt(65535);
	}

	// Return true if proper IP address received
	private static boolean handleResponseV4(DNSResponse response) {
		if (response.getAnswers().length > 0) {
			for (DNSAnswer answer: response.getAnswers()) {
				if (answer.getType() == 1) {
					return true;
				}
			}
		}
		return false;
	}

	// Return true if proper IP address received
	private static boolean handleResponseV6(DNSResponse response) {
		if (response.getAnswers().length > 0) {
			for (DNSAnswer answer: response.getAnswers()) {
				if (answer.getType() == 28) {
					return true;
				}
			}
		}
		return false;
	}

	// Get IP of next name server to contact, initiate new query to get IP if not in additional section.
	private static InetAddress getNextServer(DNSResponse response, String fqdn, boolean type, InetAddress rootNameServer) throws UnknownHostException {
		NSRecord[] records = response.getNSRecords();
		AdditionalEntry[] additionals = response.getAdditional();

		// if(true) {
		// 	System.out.println(additionals.length);
		// 	for (AdditionalEntry add: additionals) {
		// 		System.out.println(add.getName());
		// 		System.out.println(add.getType());
		// 		System.out.println(add.getData());
		// 	}
		// }

		if (records.length > 0) {
			if (additionals.length > 0) {
				for (AdditionalEntry additional: additionals) {
					// Make sure it's IPV4
					if (additional.getType() == 1 && recordsContain(additional.getName(), records)) {
						return InetAddress.getByName(additional.getData());
					}
				}
			}
			for (NSRecord record: records) {
				if (record.getType() == 2) {
					return lookupNSAddress(record.getData(), rootNameServer);
				}
			}
		}
		// No valid Answers or NSRecords.
		returnError(fqdn, type, "-6");
		return null;
	}

	// Check if NSRecords has a matching entry for given additionalInfo.
	private static boolean recordsContain(String data, NSRecord[] records) {
		//Version of data with beginning and end '.' trimmed
		String trimmedData = data.replaceAll("^\\.+", "");
		String trimmedBack = trimmedData.replaceAll("\\.+$","");
		for (NSRecord record: records) {
			if (record.getType() == 2) {
				if (!record.getData().equals(data)) {
					if (record.getData().equals(trimmedData)) {
						return true;
					} else if (record.getData().equals(trimmedBack)) {
						return true;
					}
				} else {
					return true;
				}
			}
		}
		return false;
	}

	// Checks for Rcode errors
	private static void checkRcode(DNSResponse response, String fqdn, boolean type) {
		if (response.getRcode() != 0) {
			if (response.getRcode() ==  3) {
				returnError(fqdn, type, "-1");
			} else {
				returnError(fqdn, type, "-4");
			}
		}
	}

	// Checks if corresponding fqdn has CName Answer.
	private static String checkforCN(DNSResponse response, String fqdn) {
		if (response.getAnswers().length > 0) {
			for (DNSAnswer answer: response.getAnswers()) {
				if (answer.getType() == 5 && compareFQDN(fqdn, answer.getName())) {
					return answer.getData();
				}
			}
		}
		return null;
	}

	private static boolean compareFQDN(String fqdn, String answerName) {
		String trimmedName = answerName.replaceAll("^\\.+", "");
		String trimmedBack = trimmedName.replaceAll("\\.+$","");
		if (!fqdn.equals(answerName)) {
			if (!fqdn.equals(trimmedName)) {
				return fqdn.equals(trimmedBack);
			}
		}
		return true;
	}

    private static void usage() {
	System.out.println("Usage: java -jar DNSlookup.jar rootDNS name [-6|-t|t6]");
	System.out.println("   where");
	System.out.println("       rootDNS - the IP address (in dotted form) of the root");
	System.out.println("                 DNS server you are to start your search at");
	System.out.println("       name    - fully qualified domain name to lookup");
	System.out.println("       -6      - return an IPV6 address");
	System.out.println("       -t      - trace the queries made and responses received");
	System.out.println("       -t6     - trace the queries made, responses received and return an IPV6 address");
    }
}

