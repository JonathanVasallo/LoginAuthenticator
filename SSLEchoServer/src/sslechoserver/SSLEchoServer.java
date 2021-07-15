
package sslechoserver;

/**
 * 
 *
 * @author Jonathan Vasallo
 */
import csc5055.Base32;
import csc5055.flatdb.FlatDatabase;
import csc5055.flatdb.Record;
import java.io.BufferedReader;
import javax.net.ssl.SSLServerSocketFactory;
import java.net.Socket;
import java.net.ServerSocket;
import java.util.Scanner;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Properties;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.swing.JOptionPane;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SSLEchoServer {

    public static final int PORT_NUM = 5000;
    private static final String[] fieldNames = new String[]{"Username", "Password", "Phone", "SaltIV", "HMACSha1Key"};
    private static FlatDatabase AccDB;
    private static final int COST = 2048;          // A.K.A Iterations
    private static final int BLK_SIZE = 8;
    private static final int PARALLELIZATION = 1;  // Number of parallel threads to use.
    private static final int KEY_SIZE = 128;
    private static IvParameterSpec IV;
    private static byte[] IVauth;
    private static String OKNOK = null;
    static String valueOfOTP;
    static String theEmail;
    static ArrayList<String> UsernamesCreated = new ArrayList();

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        SSLServerSocketFactory sslFact;
        ServerSocket server;
        
        AccDB = new FlatDatabase(); // database creation 

        // Set the keystore and keystore password.
        System.setProperty("javax.net.ssl.keyStore", "akeystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "chocolate");

        try {
            // Get a copy of the deafult factory. This is what ever the
            // configured provider gives.
            sslFact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

            // Set up the server socket using the specified port number.
            server = sslFact.createServerSocket(PORT_NUM);

            // Loop forever handing connections.
            while (true) {
                // Wait for a connection.
                Socket sock = server.accept();

                System.out.println("Connection received.");

                // Setup the streams for use.
                Scanner recv = new Scanner(sock.getInputStream());
                PrintWriter send = new PrintWriter(sock.getOutputStream(), true);

                // Get the line from the client.
                if(server.isClosed()==false){
                String line="";
                if(recv.hasNext()==true){
                
                line = recv.nextLine();
                }
                System.out.println("Got Line From Client " + line);
                
                if (line.startsWith("CREATE")) {
                    OpenAndCreate();
                    String[] splited = line.split(":");
                    String PassToHash = splited[2]; // the password we need to hash     [0] is CREATE [1] Username [2]  pass [3] email
                    String HashPass = Hash(PassToHash);
                    UsernamesCreated.add("FillingMemoryWithOneCell");
                    System.out.println(HashPass + " HMAC:");
                    String ivString = Base64.getEncoder().encodeToString(IV.getIV());
                    String HMACKeyString = HMACing(); 
                    
                    System.out.println("Username: " + splited[1] + "\nHashedPass" + HashPass + "\nIV: " + ivString + "\nHMAC: " + HMACKeyString);
                    
                    String[] ListToStore = new String[5];
                    ListToStore[0] = splited[1];
                    ListToStore[1] = HashPass;
                    ListToStore[2] = splited[3]; // emaill 
                    ListToStore[3] = ivString;
                    ListToStore[4] = HMACKeyString;
                    boolean UsernameDetect;
                    UsernameDetect = UsernameDuplicateDetect(splited[1]);
                    if(UsernameDetect==true){
                    send.println("DUP");  // change to DUP 
                    } else{
                    UsernamesCreated.add(splited[1]);    
                    
                    recordCreator(ListToStore); // adds to DB
                    theEmail = splited[3];
                    if (OKNOK.equals("OK")) {
                        OKNOK = OKNOK + ":" + HMACKeyString;
                        send.println(OKNOK);
                    } else if (OKNOK.equals("NOK")) {
                        // send back just this  
                        send.println("NOK");
                    }
                } // end of else 
                    // now we have to reply to client 
                } else if(line.startsWith("AUTH")){
                    // AUTH
                    boolean UsernameChecker = false;
                    String[] splitAuth = line.split(":");
                    for(int i =0;i<UsernamesCreated.size();i++){
                        if(splitAuth[1].equals(UsernamesCreated.get(i))){
                         UsernameChecker=true;  
                    }
                    }
                    if(UsernameChecker==true){
                    Record lookupRecord = AccDB.lookupRecord("Username",splitAuth[1]);
                    String fieldValue = lookupRecord.getFieldValue("SaltIV");
                    byte[] decodedSalt = Base64.getDecoder().decode(fieldValue);
                    IVauth = decodedSalt;
                    String HashPassAuth = HashAuth(splitAuth[2]);
                    System.out.println("HASHED PASS IS: "+HashPassAuth);
                    //IVauth = new IvParameterSpec(decodedSalt);
                    Record lookupRecord2 = AccDB.lookupRecord("Username",splitAuth[1]);
                    String hashpassword2compare = lookupRecord2.getFieldValue("Password");
                    //theEmail = splitAuth[3];
                    if(hashpassword2compare.equals(HashPassAuth)){
                        
                        System.out.println("Theres a match!");
                        //String theOTP = sendSms(splitAuth[1],splitAuth[2],splitAuth[3]);
                        //EmailSender(theOTP);
                        send.println("OK:AUTH:"+theEmail);
                    }else{
                     System.out.println("No Match Found!");   
                    send.println("NOK");
                    }
                

                System.out.println("Client said: " + line);

                // Echo the line back.
                // Close the connection.
                sock.close();
                    } else{
                        send.println("NOK");
                    }
            } else if(line.startsWith("Close")){
              sock.close();
            } else{
                System.out.println("Client Closed");
            }
            }            
        }
        }catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }
    /*
    OpenAndCreate opens the database we store into or creates it if it does 
    not exist already.
    */
    public static void OpenAndCreate() {
        if (AccDB.createDatabase("AccDB.db", fieldNames)) {
            //AccDB.saveDatabase(); // optional 
            System.out.println("DB CREATED");
        } else {
            AccDB.openDatabase("AccDB.db");
        }
    }

    /*
    Hash Method takes in a string that is the password the user provides to the
    server and generates a IV that is used to SCRYPT hash the password and return.
    @params thePasstoHash = password unaltered
    @return hashString - the password after hashing 
    */
    public static String Hash(String thePasstoHash) throws NoSuchAlgorithmException, InvalidKeySpecException {

        Security.addProvider(new BouncyCastleProvider());
        SecureRandom rand;               // A secure random number generator.
        byte[] rawIV = new byte[16];
        rand = new SecureRandom();
        rand.nextBytes(rawIV);
        IvParameterSpec Iv = new IvParameterSpec(rawIV);
        IV = Iv;
        SecretKeyFactory scrypt = SecretKeyFactory.getInstance("SCRYPT");
        ScryptKeySpec spec = new ScryptKeySpec(thePasstoHash.toCharArray(), rawIV, COST, BLK_SIZE, PARALLELIZATION, KEY_SIZE);
        byte[] hash = scrypt.generateSecret(spec).getEncoded();
        String hashString = Base64.getEncoder().encodeToString(hash);
        return hashString;

    }
    /*
    HashAuth Method takes in a string that is the password of the auth user provides to the
    server and uses the IV that was previously used to create another hashed password 
    and returns it as a string. 
    @params thePasstoHash - the password unaltered from the client
    @return hashString - The Hashed Password using ScryptKeySparc
    */
    public static String HashAuth(String thePasstoHash) throws NoSuchAlgorithmException, InvalidKeySpecException {

        Security.addProvider(new BouncyCastleProvider());
        SecretKeyFactory scrypt = SecretKeyFactory.getInstance("SCRYPT");
        ScryptKeySpec spec = new ScryptKeySpec(thePasstoHash.toCharArray(), IVauth, COST, BLK_SIZE, PARALLELIZATION, KEY_SIZE);
        byte[] hash = scrypt.generateSecret(spec).getEncoded();
        String hashString = Base64.getEncoder().encodeToString(hash);
        return hashString;

    }
    
    /*
    HMACing method generates a HMACSHA1 key and turns it into a Base32 string
    then returns it. 
    @return Base32.encodeToString(tag, true) - Converted HMAC Tag to a String
    */
    public static String HMACing() throws NoSuchAlgorithmException, InvalidKeyException {

        SecretKey key;
        byte[] tag;

        // Get a new HMAC instance.
        Mac hmac = Mac.getInstance("HmacSHA1");

        // Construct an key for the HMAC.
        KeyGenerator hmacKeyGen = KeyGenerator.getInstance("HmacSHA1");
        key = hmacKeyGen.generateKey();

        // Set the key for the HMAC.
        hmac.init(key);

        // Compute the HMAC of a string.
        tag = hmac.doFinal(
                "An HMAC is an integrity protection mechanism.".getBytes());

        // Display the tag.
        System.out.println("Tag: " + Base32.encodeToString(tag, true));
        return Base32.encodeToString(tag, true);

    }
    /*
    recordCreator inserts the records for a array provided and adds them to the
    provided database.
    @params listt - a Array containing 
    1. Username
    2. Hashed Password
    3. Email
    4. IV
    5. HMAC Key
    */
    public static void recordCreator(String[] listt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeyException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {

        Record r = new Record(fieldNames, listt);
        if (AccDB.insertRecord(r)) {
            // successflly aDDED
            AccDB.saveDatabase();
            OKNOK = "OK";
        } else {
            OKNOK = "NOK";
            System.out.println("Values were NOT added to the database");
        }

    }

    /**
     * This method converts a long value into an 8 - byte value .
     *
     * @param num the number to convert to bytes .
     * @return an array of 8 bytes representing the number num.
     */
    private byte[] longToBytes(long num) {
        byte[] res = new byte[8];
// Decompose the a long type into byte components .
        for (int i = 7; i >= 0; i --){
            res[i] = (byte)(num & 0xFF);
           num >>= 8;
        }
        return res;
    }
    /*
    This method detects whether or not the username being created
    has been taken already
    @params Username - the Username the client entered that is being checked
    @return CheckerUsername - a boolean value, if true Username is a duplicate
    */
    public static boolean UsernameDuplicateDetect(String Username){
        boolean CheckerUsername = false;
        for(int i=0; i < UsernamesCreated.size();i++){
            if(Username.equals(UsernamesCreated.get(i))){
            CheckerUsername = true; 
            // if the username exists in the Database it is a duplicate 
            //and we must send a warning to client    
            }
        }
        return CheckerUsername;
        
    }
    } // end of SSLEchoServer Class 


