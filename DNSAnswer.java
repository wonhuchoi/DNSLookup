import java.net.InetAddress;



public class DNSAnswer {
    public String NAME;
    private int TYPE;
    private int CLASS;
    private int TTL;
    private int RDLENGTH;
    public String RDATA;

    public DNSAnswer (String Name, int type, int answerClass, int ttl, int rdlength, String rdata) {
        this.NAME = Name;
        this.TYPE = type;
        this.CLASS = answerClass;
        this.TTL = ttl;
        this.RDLENGTH = rdlength;
        this.RDATA = rdata;
	}

    public int getType() {
        return this.TYPE;
    }

    public String getName() {
        return this.NAME;
    }

    public int getTTL() {
        return this.TTL;
    }

    public int getLength() {
        return this.RDLENGTH;
    }

    public String getData() {
        return this.RDATA;
    }

}
