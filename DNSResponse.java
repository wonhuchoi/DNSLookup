import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.lang.StringBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.nio.charset.Charset;  

public class DNSResponse {
    private int queryID;                  // this is for the response it must match the one in the request 
    private int queryCount = 0;
    private boolean decoded = false;      // Was this response successfully decoded
    private boolean authoritative = false;// Is this an authoritative record
    private boolean truncated = false;    // Is this a truncated record
    private int OpCode;
    private int RCODE;
    private DNSAnswer[] answers;
    private AdditionalEntry[] additionalInfo;
    private NSRecord[] NSRecords;

    private static Byte NAME_SEPERATOR = 0x2E;

    // When in trace mode you probably want to dump out all the relevant information in a response

	void dumpResponse() {
		


    }

    private enum RRTypes {
        ANSWER,
        NSRECORD,
        ADDITIONALINFO
    }

    public int getQueryID() {
        return this.queryID;
    }

    public int getNSCount() {
        return this.NSRecords.length;
    }

    public int getAdditionalInfoCount() {
        return this.additionalInfo.length;
    }

    public int getAnswersCount() {
        return this.answers.length;
    }
    
    public boolean isAuthoritative() {
        return this.authoritative;
    }

    public DNSAnswer[] getAnswers() {
        return this.answers;
    }

    public AdditionalEntry[] getAdditional() {
        return this.additionalInfo;
    }

    public NSRecord[] getNSRecords() {
        return this.NSRecords;
    }

    public int getRcode() {
        return this.RCODE;
    }


	public DNSResponse (byte[] data, int len) throws IOException, Exception {
        try{
            int idx_data = 0;
            ByteArrayInputStream is = new ByteArrayInputStream(data);
            DataInputStream dis = new DataInputStream(is);
            // The following are probably some of the things 
            // you will need to do.
            // Extract the query ID
            this.queryID = dis.readUnsignedShort();
            int flagsByte = dis.readUnsignedShort();
            // checks to see if the packet is an answer by checking the QR flag
            if ((flagsByte & 0x8000) == 1) {
                throw new Exception("this response is not an answer");
            }
            // parse OpCode
            this.OpCode = (flagsByte & 0x7800)>>11;
            // parse AA
            this.authoritative = (flagsByte & 0x400)>>10 == 1 ? true : false;
            // parse TC flag
            this.truncated = (flagsByte & 0x200)>>9 == 1 ? true : false;
            // parse RCODE
            this.RCODE = (flagsByte & 0xF);

            // parse Query Count
            this.queryCount = dis.readUnsignedShort();
            // parse Answer Count
            this.answers = new DNSAnswer[dis.readUnsignedShort()];
            // parse NS Count
            this.NSRecords = new NSRecord[dis.readUnsignedShort()];
            // parse Additional Info Length
            this.additionalInfo = new AdditionalEntry[dis.readUnsignedShort()];
            idx_data += 12; // Offset after reading header
            idx_data = this.processQuery(data, idx_data, this.queryCount); // process returned queries
            idx_data = this.processRecords(data, idx_data, this.getAnswersCount(), RRTypes.ANSWER); // process returned answers
            idx_data = this.processRecords(data, idx_data, this.getNSCount(), RRTypes.NSRECORD); // process returned NSCount
            idx_data = this.processRecords(data, idx_data, this.getAdditionalInfoCount(), RRTypes.ADDITIONALINFO); // process returned Additional entries
            // determine answer count
            // Make sure the message is a query response and determine
            // if it is an authoritative response or not

            // determine NS Count

            // determine additional record count

            // Extract list of answers, name server, and additional information response 
            // records
        } catch (IOException e) {
            throw new IOException();

        } catch (Exception e) {
            throw new Exception();
        }
	}

    private int processQuery(byte[] data, int idx, int entryCount) throws IOException {
        int ret = idx;
        int curr = idx;
        ByteArrayInputStream is = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(is);
        ArrayList<Byte> qnameArrayBytes;
        byte[] buf;
        int bytesToRead = 0;
        for (int i = 0; i < entryCount; ++i) {
            qnameArrayBytes = new ArrayList<Byte>();
            while(data[curr] != 0x00) {
                if(bytesToRead == 0 && ((data[curr] & 0xc0) == 0xc0)) {
                    byte[] bb = new byte[2];
                    bb[0] = flipFirstTwobits(data[curr]); // take off pointer indicator
                    bb[1] = (data[curr + 1]);
                    curr = byteArrayToInt(bb) & 0xff;
                    ret += 2; // increment ret pointer
                    if (curr == 0) {
                        curr = ret;
                        break;
                    }
                } else {
                    if (bytesToRead <= 0) {
                        if(qnameArrayBytes.size() > 0)
                            qnameArrayBytes.add(NAME_SEPERATOR); // insert a "."
                        bytesToRead = data[curr];
                    } else {
                        qnameArrayBytes.add(data[curr]);
                        --bytesToRead;
                    }
                    ++curr;
                }
                ret = Math.max(ret, curr);
            }
            ret += 1; // increment once
            // instantiate variables to hold info about Record
            int type;
            int answerClass;
            int ttl;
            try{
                // reading Quertion Type;
                buf = new byte[2];
                
                this.readBytesWithOffset(data, buf, ret, 2);
                type = byteArrayToInt(buf);
                ret += 2;
                // reading Question Class;
                buf = new byte[2];
                this.readBytesWithOffset(data, buf, ret, 2);
                answerClass = byteArrayToInt(buf);
                ret += 2;
            } catch (IOException e) {
                throw new IOException();
            }
        }
        return ret;
    }

    private int readBytesWithOffset(byte[] arrayToRead, byte[] arrayToPopulate, int offset, int bytesToRead) throws IOException {
        int ret = 0;
        for (int i = offset; i < offset + bytesToRead; ++i, ret++) {
            if(offset + bytesToRead >= arrayToRead.length){
                throw new IOException("Offset + number of bytes to read must be smaller than array length. offset: " +offset+" bytes to read: "+bytesToRead);
            }
            arrayToPopulate[ret] = arrayToRead[i];
        }
        return ret;
    }

    private byte[] ByteArrayListToArray(ArrayList<Byte> a) {
        byte[] ret = new byte[a.size()];
        for (int i = 0; i < a.size(); ++i) {
            ret[i] = a.get(i);
        }
        return ret;
    }

    private int processRecords(byte[] data, int idx, int entryCount, RRTypes recordType) throws IOException {
        int ret = idx;
        int curr = idx;
        ByteArrayInputStream is = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(is);
        ArrayList<Byte> nameArrayBytes;
        byte[] buf;
        for (int i = 0; i < entryCount; ++i) {
            nameArrayBytes = new ArrayList<Byte>();
            int isCompressed = 0;
            int bytesToRead = 0;
            boolean hasChanged = false;
            curr = ret;
            while(data[curr] != 0x00) {
                if(bytesToRead == 0 && ((data[curr] & 0xc0) == 0xc0)) {
                    byte[] bb = new byte[2];
                    bb[0] = flipFirstTwobits(data[curr]); // take off pointer indicator
                    bb[1] = (data[curr + 1]);
                    curr = byteArrayToInt(bb) & 0xff;
                    isCompressed = 1;
                    if (curr == 0) {
                        curr = ret;
                        break;
                    }
                } else {
                    if (bytesToRead <= 0) {
                        if(nameArrayBytes.size() > 0)
                            nameArrayBytes.add(NAME_SEPERATOR); // insert a "."
                        bytesToRead = data[curr];
                    } else {
                        nameArrayBytes.add(data[curr]);
                        --bytesToRead;
                    }
                    ++curr;
                }
                ret = Math.max(ret, curr);
            }
            ret += 1 + isCompressed;
            // instantiate variables to hold info about Record
            int type;
            int answerClass;
            int ttl;
            int rdlength;
            String rdata;
            try{
                // reading Answer Type;
                buf = new byte[2];
                this.readBytesWithOffset(data, buf, ret, 2);
                type = byteArrayToInt(buf);
                ret += 2;
                // reading Answer Class;
                buf = new byte[2];
                this.readBytesWithOffset(data, buf, ret, 2);
                answerClass = byteArrayToInt(buf);
                ret += 2;
                // reading Answer TTL;
                buf = new byte[4];
                this.readBytesWithOffset(data, buf, ret, 4);
                ttl = byteArrayToInt(buf);
                ret += 4;
                // reading Answer rdlength;
                buf = new byte[2];
                this.readBytesWithOffset(data, buf, ret, 2);
                rdlength = byteArrayToInt(buf);
                ret += 2;
                // reading RDATA
                buf = new byte[rdlength];
                this.readBytesWithOffset(data, buf, ret, rdlength);
                rdata = readRDATA(data, ret, type, rdlength);
                ret += rdlength;constructRREntry(new String(ByteArrayListToArray(nameArrayBytes)), i, type, answerClass, ttl, rdlength, rdata, recordType);
            } catch (IOException e) {
                throw new IOException();
            }
        }
        return ret;
    }

    private void constructRREntry(String Name, int index, int type, int answerClass, int ttl, int rdlength, String rdata, RRTypes recordType) {
        switch(recordType) {
            case ANSWER:
                this.answers[index] = new DNSAnswer(Name, type, answerClass, ttl, rdlength, rdata);
                break;
            case NSRECORD:
                this.NSRecords[index] = new NSRecord(Name, type, answerClass, ttl, rdlength, rdata);
                break;
            case ADDITIONALINFO:
                this.additionalInfo[index] = new AdditionalEntry(Name, type, answerClass, ttl, rdlength, rdata);
                break;
            default:
                break;
        }
    }

    private byte flipFirstTwobits(byte b) {
        int mask = 0xC0;
        int b2 = (int)b;
        return (byte)(mask^b2);
    }

    private int byteArrayToInt(byte[] a){
        int ret = 0;
        for(int i = 0; i < a.length; ++i) {
            ret |= ((a[i] & 0xff) << (8*(a.length - i - 1)));
        }
        return ret;
    }
    
    private short byteArrayToShort(byte[] a){
        short ret = 0;
        for(int i = 0; i < a.length; ++i) {
            ret += (ret<<8) + a[i];
        }
        return ret;
    }

    private String readRDATA(byte[] data, int idx, int type, int length) {
        String ret = "";
        switch(type) {
            case 1:
                ret = readIPv4(data, idx, length);
                break;
            case 2:
                ret = readAddress(data, idx);
                break;
            case 5:
                ret = readAddress(data, idx);
                break;
            case 28:
                ret = readIPv6(data, idx, length);
                break;
            default:
                break;
        }
        return ret;
    }

    private String readIPv4(byte[] data, int idx, int length) {
        int ret = idx;
        int curr = idx;
        StringBuffer sb = new StringBuffer();
        byte[] buf;
        int bytesToRead = 0;
        int i = 0;
        while(i < length) {
            int val = data[curr] & 0xff;
            sb.append(val);
            if (i != length-1) {
                sb.append('.');
            }
            i++;
            ++curr;
        }
        ret = Math.max(ret, curr);
        return sb.toString();
    }

   private String readIPv6(byte[] data, int idx, int length) {
        int ret = idx;
        int curr = idx;
        StringBuffer sb = new StringBuffer();
        byte[] buf;
        int bytesToRead = 0;
        int i = 0;
        while(i < length) {
            int val = data[curr] & 0xff;
            int secVal = data[curr + 1] & 0xff;
            sb.append(Integer.toHexString(val));
            if (secVal < 16) {
                sb.append(0);
            }
            sb.append(Integer.toHexString(secVal));
            if (i != length-2) {
                sb.append(':');
            }
            i = i + 2;
            curr = curr + 2;
        }
        ret = Math.max(ret, curr);
        return TrimIPV6AddressString(sb);
        // return sb.toString();
    }

    private String TrimIPV6AddressString(StringBuffer sb) {
        String sbToString = sb.toString();
        String ret = "";
        String[] stringArray = sbToString.split(":");
        for (int i = 0; i < stringArray.length; ++i) {
            stringArray[i] = stringArray[i].replaceFirst("^0+(?!$)", "");
        }
        for (int i = 0; i < stringArray.length; ++i) {
            String s = stringArray[i];
            ret += s;
            if (i < stringArray.length - 1)
                ret += ":";
        }
        return ret;
    }

    private String readAddress(byte[] data, int idx) {
        int ret = idx;
        int curr = idx;
        ByteArrayInputStream is = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(is);
        ArrayList<Byte> nameArrayBytes;
        byte[] buf;
        int bytesToRead = 0;
        nameArrayBytes = new ArrayList<Byte>();
        while(data[curr] != 0x00) {
            if(bytesToRead == 0 && ((data[curr] & 0xff) == 0xc0)) {
                byte[] bb = new byte[2];
                bb[0] = flipFirstTwobits(data[curr]); // take off pointer indicator
                bb[1] = (data[curr + 1]);
                curr = byteArrayToInt(bb) & 0xff;
                ret += 2; // increment ret pointer
                if (curr == 0) {
                    curr = ret;
                    break;
                }
            } else {
                if (bytesToRead <= 0) {
                    if (nameArrayBytes.size() != 0)
                        nameArrayBytes.add(NAME_SEPERATOR); // insert a "."
                    bytesToRead = data[curr];
                } else {
                    nameArrayBytes.add(data[curr]);
                    --bytesToRead;
                }
                ++curr;
            }
            ret = Math.max(ret, curr);
        }
        return new String(ByteArrayListToArray(nameArrayBytes));
    }
}
