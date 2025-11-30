/**
 * Copyright (c) 2010-2015, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

 // 22okt24: renamed 192.168.1.130 e001 to 192.168.1.114

/*
fyi for digest authentication:  
	doc: https://usamadar.com/2012/06/11/implementing-http-digest-authentication-in-java/
	gist: https://gist.github.com/usamadar/2912088
fyi: curl source: [https://github.com/curl/curl/blob/e052859759b34d0e05ce0f17244873e5cd7b457b/lib/vauth/digest.c#L710-L723]
wiki: https://en.wikipedia.org/wiki/Digest_access_authentication
		MD5 
		It applies a cyrographic hashing usage of nonce/random values function to the username and password
		HA1 = MD5(username:realm:password)
		HA2 = MD5(method:digestURI)    (qop directive'is "auth"
		response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)

		uri = 
		WWW-Authenticate: Digest realm="testrealm@host.com",
                       qop="auth,auth-int",							edimax uses auth
                       nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",		Nonces are used to make a request unique. 
                       opaque="5ccc069c403ebaf9f0171e9517f40e41"

		Authorization: Digest username="Mufasa",
                    realm="testrealm@host.com",
                    nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",			md5-32bytes
                    uri="/dir/index.html",							
                    qop=auth,
                    nc=00000001,
                    cnonce="0a4f113b",
                    response="6629fae49393a05397450978507c4ef1",			md5-32bytes
                    opaque="5ccc069c403ebaf9f0171e9517f40e41"				md5-32bytes

				 The "response" value is calculated in three steps, as follows. 
				 Where values are combined, they are delimited by colons.

   		The MD5 hash of the combined username, authentication realm and password is calculated. The result is referred to as HA1.
   		The MD5 hash of the combined method and digest URI is calculated, e.g. of "GET" and "/dir/index.html". The result is referred to as HA2.
   		The MD5 hash response of the combined fields: md5(ha1:nonce:cnonce:ha2)
					HA1 result, 
					server nonce (nonce), 
					request counter (nc), 
					client nonce (cnonce), 
					quality of protection code (qop) and 
					HA2 result is calculated. 

	edimax:	> Authorization: Digest 
			  username="admin", 
			  realm="SP1101W", 
			  nonce="e4bd110b794fd9a431f4550d3bb73750", 
			  uri="/smartplug.cgi", 
			  cnonce="MmU4MDc1OTg1N2RmNmM1OThmYTgzM2FjYmZiMzY3N2Q=", 
			  nc=00000001,
			  qop=auth, 
			  response="f4df1d405d85fd41377fecc401536a24"

   	HA1 = MD5( "Mufasa:testrealm@host.com:Circle Of Life" ) = 939e7578ed9e3c518a452acee763bce9
	HA2 = MD5( "GET:/dir/index.html" ) = 39aff3a2bab6126f332b942af96d3366
	Response = MD5( "939e7578ed9e3c518a452acee763bce9:\			HA1 = MD5( "Mufasa:testrealm@host.com:Circle Of Life" )
                   	dcd98b7102dd2f0e8b11d0f600bfb0c093:\			(nonce from server)
                   	00000001:0a4f113b:auth:\						(cnonce, client generated)
                   	39aff3a2bab6126f332b942af96d3366" ) 			HA2 = MD5( "GET:/dir/index.html" )
				= 6629fae49393a05397450978507c4ef1

*/
package org.openhab.binding.edimax.internal;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.math.BigInteger; 		// used to resolve String.format("%032X", new BigInteger(1, md5sum)); 
import java.net.HttpURLConnection;	// https://docs.oracle.com/javase/8/docs/api/java/net/HttpURLConnection.html
import java.net.URL;				// https://github.com/openjdk/jdk/tree/309b929147e7dddfa27879ff31b1eaad271def85/test/jdk/java/net

import javax.xml.bind.DatatypeConverter;

import org.openhab.binding.edimax.internal.commands.GetCurrent;
import org.openhab.binding.edimax.internal.commands.GetMAC;
import org.openhab.binding.edimax.internal.commands.GetPower;
import org.openhab.binding.edimax.internal.commands.GetState;
import org.openhab.binding.edimax.internal.commands.SetState;

import org.slf4j.Logger; // 15okt24 Ptro checkout URL communication
import org.slf4j.LoggerFactory; // 15okt24 Ptro checkout URL communication
import java.util.Date; // 15okt24 Ptro checkout URL Authentication nonce
import java.util.Random; // 15okt24 Ptro checkout URL Authentication nonce
// import org.apache.commons.codec.digest.DigestUtils; // 15okt24 Ptro checkout URL Authentication nonce
import java.security.MessageDigest; // 15okt24 Ptro checkout URL Authentication nonce		
import java.security.NoSuchAlgorithmException; // 15okt24 Ptro checkout URL Authentication nonce		
// import java.security.*;
import org.apache.commons.lang.StringUtils; // 15okt24 Ptro checkout URL Authentication nonce
import java.io.UnsupportedEncodingException;

import java.util.HashMap; // 15okt24 Ptro checkout URL Authentication keying Authentication headers

// trying md5 from this: // does not work using mvn
// import org.apache.commons.codec.digest.DigestUtils;

/**
 * Sends commands and returns responses for the edimax device, using it's http
 * interface.
 * 
 * @author Heinz
 *
 */
public class HTTPSend {

	/**
	 * Logger. 15okt24 Ptro checkout URL communication
	 */
	private static final Logger logger = LoggerFactory
			.getLogger(EdimaxBinding.class);
	// private static final com.sun.org.slf4j.internal.Logger logger = LoggerFactory
	// 		.getLogger(EdimaxBinding.class);

	public static final String XML_HEADER = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n";

	private static final String defaultUser = "admin";
	// private static final String defaultPassword = "1234";
	private static final String defaultPassword = "edimax001"; // 15okt24 ptro force password

	protected static final int PORT = 10000;

	private static String completeURL(String anIp) {
		return "http://" + anIp;
	}

	private String password;

	private static String authMethod = "auth"; // ptro 15okt24 for authentication
	private static String realm = "example.com"; // ptro 15okt24 for authentication
	// public String nonce; // ptro 15okt24 for authentication
	private static String nonce; // ptro 15okt24 for authentication

	public HTTPSend() {
		this(defaultPassword);
	}

	public HTTPSend(String aPw) {
		password = aPw;
	}

	/**
	 * Switch to.
	 * 
	 * @param anIp
	 * @param newState
	 * @return
	 * @throws IOException
	 */
	public Boolean switchState(String anIp, Boolean newState)
			throws IOException {
		String completeUrl = completeURL(anIp);
		ConnectionInformation ci = new ConnectionInformation(defaultUser,
				password, completeUrl, PORT);

		SetState setS = new SetState(newState);
		return setS.executeCommand(ci);
	}

	/**
	 * Returns state for device with given IP.
	 * 
	 * @param anIp
	 * @return
	 * @throws IOException
	 */
	public Boolean getState(String anIp) throws IOException {
		String completeUrl = completeURL(anIp);
		ConnectionInformation ci = new ConnectionInformation(defaultUser,
				password, completeUrl, PORT);

		GetState getS = new GetState();
		return getS.executeCommand(ci);
	}

	/**
	 * Receive the MAC address.
	 * 
	 * @param anIp
	 * @return
	 * @throws IOException
	 */
	public String getMAC(String anIp) throws IOException {
		String completeUrl = completeURL(anIp);
		ConnectionInformation ci = new ConnectionInformation(defaultUser,
				password, completeUrl, PORT);

		GetMAC getC = new GetMAC();
		return getC.executeCommand(ci);
	}

	/**
	 * Returns the current.
	 * 
	 * @param anIp
	 * @return
	 * @throws IOException
	 */
	public BigDecimal getCurrent(String anIp) throws IOException {
		String completeUrl = completeURL(anIp);
		ConnectionInformation ci = new ConnectionInformation(defaultUser,
				password, completeUrl, PORT);

		GetCurrent getC = new GetCurrent();
		return getC.executeCommand(ci);
	}

	/**
	 * Gets the actual power.
	 * 
	 * @param anIp
	 * @return
	 * @throws IOExceptionif
	 *                       (mac != null) { // found a device! Device d = new
	 *                       Device();
	 *                       d.ip = portScanUsage.getIp(); d.mac = mac;
	 *                       discovered.add(d);
	 *                       }
	 */
	public BigDecimal getPower(String anIp) throws IOException {
		String completeUrl = completeURL(anIp);
		ConnectionInformation ci = new ConnectionInformation(defaultUser,
				password, completeUrl, PORT);

		GetPower getC = new GetPower();
		return getC.executeCommand(ci);
	}

	/**
	 * prepares an header for getting WWW-Authentication (ptro 15okt24)
	 *
	 * @param headerString
	 * @return
	 */
	// public String getAuthenticateHeader() {
	private static String getAuthenticateHeader() {
		String header = "";
		nonce = calculateNonce("1234");
		header += "Digest realm=\"" + realm + "\",";
		if (!StringUtils.isBlank(authMethod)) {
			header += "qop=" + authMethod + ",";
		}
		header += "nonce=\"" + nonce + "\",";
		header += "opaque=\"" + getMD5(realm + nonce) + "\"";

		return header;
	}

	/**
	 * 15okt24 ptro
	 * Convert a string representation of hexadecimal to a byte array.
	 *
	 * For example: String s = "00010203" returned byte array is {0x00, 0x01, 0x03}
	 *
	 * @param hex hex input string
	 * @return byte array equivalent to hex string
	 **/
	public static byte[] hexStringToByteArray(String hex) {
		// String commandString = baseString + rfAddress;
		// String encodedString =
		// Base64.encodeBase64String(Utils.hexStringToByteArray(commandString));
		String s = hex.replace(" ", "");
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	private static final String HEXES = "0123456789ABCDEF";

	/**
	 * 15okt24 ptro
	 * Convert a byte array to a string representation of hexadecimals.
	 *
	 * For example: byte array is {0x00, 0x01, 0x03} returned String s =
	 * "00 01 02 03"
	 *
	 * @param raw byte array
	 * @return String equivalent to hex string
	 **/
	public static String getSpacedHex(byte[] raw) {
		if (!(raw != null)) {
			return "";
		}
		final StringBuilder hex = new StringBuilder(3 * raw.length);
		for (final byte b : raw) {
			hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F))).append(" ");
		}
		hex.delete(hex.length() - 1, hex.length());
		return hex.toString();
	}

	public static String getHex(byte[] raw) {
		if (!(raw != null)) {
			return "";
		}
		final StringBuilder hex = new StringBuilder(2 * raw.length);
		for (final byte b : raw) {
			hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
		}
		return hex.toString();
	}

	/**
	 * 15okt24 ptro
	 * Calculate the nonce based on fixed value
	 *
	 * @return
	 */
	// public String calculateNonce() {
	private static String calculateNonce(String input2_data) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5sum = md.digest(input2_data.getBytes());
			return String.format("%032X", new BigInteger(1, md5sum));
			// f.e. (16bytes) md5=4817E5892BF8AB093A33460D892B8FF9 using
			// calculateNonce=testedimax001
		} catch (NoSuchAlgorithmException e) {
			logger.error("calculateNonce: This version of Java does not support MD5 hashing");
			return "";
		}
		/*
		 * Date d = new Date();
		 * SimpleDateFormat f = new SimpleDateFormat("yyyy:MM:dd:hh:mm:ss");
		 * String fmtDate = f.format(d);
		 * Random rand = new Random(100000);
		 * Integer randomInt = rand.nextInt();
		 * return DigestUtils.md5Hex(fmtDate + randomInt.toString());
		 */

		/*
		 * sof old:
		 * // public String calculateNonce() {
		 * private static String calculateNonce() {
		 * 
		 * try {
		 * MessageDigest md5 = MessageDigest.getInstance("MD5");
		 * // return URLEncoder.encode(str, StandardCharsets.UTF_8.name());
		 * try {
		 * // return new
		 * String(md5.digest(("testedimax001").getBytes("UTF-8")),"UTF-8");
		 * return new String(md5.digest(("testedimax001").getBytes()),"UTF-8");
		 * } catch (UnsupportedEncodingException e) {
		 * throw new UnsupportedOperationException("UTF-8 not supported");
		 * }
		 * // byte array tot string
		 * [https://www.geeksforgeeks.org/java-program-to-convert-byte-array-to-string/]
		 * } catch (NoSuchAlgorithmException e) {
		 * logger.error("This version of Java does not support MD5 hashing");
		 * return "";
		 * }
		 * }
		 * eof old
		 */
	}

	/**
	 * 15okt24 ptro
	 * Calculate md5 sum
	 *
	 * @return
	 */
	private static String calculateMd5(String input_data) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5sum = md.digest(input_data.getBytes());
			String output = String.format("%032X", new BigInteger(1, md5sum));
			return output.toLowerCase();
			// f.e. (16bytes) md5=4817E5892BF8AB093A33460D892B8FF9 using
			// calculateNonce=testedimax001
		} catch (NoSuchAlgorithmException e) {
			logger.error("calculateMd5: This version of Java does not support MD5 hashing");
			return "";
		}

	}

	/**
	 * 15okt24 ptro
	 * Gets the Authorization header string minus the "AuthType" and returns a
	 * hashMap of keys and values
	 *
	 * @param headerString
	 * @return
	 */
	// private HashMap<String, String> parseHeader(String headerString) {
	private static HashMap<String, String> parseHeader(String headerString) {
		// seperte out the part of the string which tells you which Auth scheme is it
		String headerStringWithoutScheme = headerString.substring(headerString.indexOf(" ") + 1).trim();
		HashMap<String, String> values = new HashMap<String, String>();
		String keyValueArray[] = headerStringWithoutScheme.split(",");
		for (String keyval : keyValueArray) {
			if (keyval.contains("=")) {
				String key = keyval.substring(0, keyval.indexOf("="));
				String value = keyval.substring(keyval.indexOf("=") + 1);
				values.put(key.trim(), value.replaceAll("\"", "").trim());
			}
		}
		return values;
	}

	/*
	 * // read:
	 * [https://stackoverflow.com/questions/415953/how-can-i-generate-an-md5-hash-in
	 * -java]
	 * 
	 * public static byte[] md5(byte[] source) throws MiIoCryptoException {
	 * try {
	 * MessageDigest m = MessageDigest.getInstance("MD5");
	 * return m.digest(source);
	 * } catch (NoSuchAlgorithmException e) {
	 * throw new MiIoCryptoException(e.getMessage(), e);
	 * }
	 * }
	 * 
	 * 
	 * 
	 * The compute the hash by doing one of:
	 * Feed the entire input as a byte[] and calculate the hash in one operation
	 * with md.digest(bytes).
	 * Feed the MessageDigest one byte[] chunk at a time by calling
	 * md.update(bytes). When you're done adding input bytes, calculate the hash
	 * with md.digest().
	 * The byte[] returned by md.digest() is the MD5 hash
	 * --------------------------------------------------------------
	 * import java.security.*;
	 * ..
	 * byte[] bytesOfMessage = yourString.getBytes("UTF-8");
	 * 
	 * MessageDigest md = MessageDigest.getInstance("MD5");
	 * byte[] theMD5digest = md.digest(bytesOfMessage);
	 * --------------------------------------------------------------
	 * 
	 * protected String createResponse(String challenge) {
	 * String handshake = challenge.concat("-").concat(config.getPassword());
	 * MessageDigest md5;
	 * try {
	 * md5 = MessageDigest.getInstance("MD5");
	 * } catch (NoSuchAlgorithmException e) {
	 * logger.error("This version of Java does not support MD5 hashing");
	 * return "";
	 * }
	 * byte[] handshakeHash;
	 * try {
	 * handshakeHash = md5.digest(handshake.getBytes("UTF-16LE"));
	 * } catch (UnsupportedEncodingException e) {
	 * logger.error("This version of Java does not understand UTF-16LE encoding");
	 * return "";
	 * }
	 * String response = challenge.concat("-");
	 * for (byte handshakeByte : handshakeHash) {
	 * response = response.concat(String.format("%02x", handshakeByte));
	 * }
	 * return response;
	 * }
	 */

	// private String getOpaque(String domain, String nonce) {
	public static String getMD5(String domain_nonce) {
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			// return new String( md5.digest( (domain+nonce).getBytes("UTF-8") ),"UTF-8" );
			try {
				return new String(md5.digest((domain_nonce).getBytes("UTF-8")), "UTF-8"); // array
			} catch (UnsupportedEncodingException e) {
				throw new UnsupportedOperationException("UTF-8 not supported");
			}
			// byte array tot string
			// [https://www.geeksforgeeks.org/java-program-to-convert-byte-array-to-string/]
		} catch (NoSuchAlgorithmException e) {
			logger.error("This version of Java does not support MD5 hashing");
			return "";
		}
		// return DigestUtils.md5Hex(domain + nonce);
	}

	public static String executePost(String targetURL, int targetPort,
		String targetURlPost, String urlParameters, String username,String password) 
		throws IOException	{
		String complete = targetURL + ":" + targetPort + "/" + targetURlPost;
		String smartplug_dir = "edimax/";			// on real plug make this ""
		String smartplug_page = "imartplug.cgi";	// on real plug make this "/smartplug.cgi"

		//	complete = "http://www.ptro.nl/" + smartplug_dir + smartplug_page ;
		smartplug_dir = ""; 
		smartplug_page = "smartplug.cgi";

		logger.warn(" Warning url complete=" + complete + ", urlParameters=" + urlParameters); // 15okt24 Ptro debug why we cannot
																					// connect edimax
		// http://192.168.1.114:10000/smartplug.cgi urlParameters=<?xml version="1.0"
		// encoding="UTF8"?>
		// <SMARTPLUG id="edimax"><CMD
		// id="get"><Device.System.Power.State/></CMD></SMARTPLUG>

		// get should return <SMARTPLUG id="edimax"> <CMD
		// id="get"><Device.System.Power.State>ON</Device.System.Power.State>
		// </CMD></SMARTPLUG>
		// hoeever we get a HTTP/1.1 401 Unauthorized response body
		HttpURLConnection connection  = null;		// first for basic authentication
		HttpURLConnection connection2  = null;		// first for basic authentication
		// StringBuilder response = null;
		StringBuilder response = new StringBuilder("");
		response.append("");
		try {
			// Create connection , read:
			// [https://www.geeksforgeeks.org/how-to-use-httpurlconnection-for-sending-http-post-requests-in-java/]
			// HttpURLConnection: GET, POST, PUT, and DELETE

			// connection = (HttpURLConnection) new URL(complete).openConnection(); // fieldtype java.net.HttpURLConnection; -->
			
			URL url = new URL(complete);
			connection = (HttpURLConnection) url.openConnection(); // fieldtype java.net.HttpURLConnection; -->
							// HttpURLConnection connection is opened just creates a new Socket. 
							// The actual Connect doesn't happens until getInputStream(). I

							// note: proxy to re-use is meaningless here as it require a secondary thread for proxy
							// need to create a Proxy object for it. Create one as below:
							// Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyServer, Integer.parseInt(proxyPort)));
							// Now use this proxy to create the HttpURLConnection object.
							// HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection(proxy);

			/*
			 * // does not work: java.io.IOException: Server returned HTTP response code:
			 * 400 (invalid request.... )
			 * 401 unauthorised
			 * 411 Already connected
			 * // - sof insert to check for 401 body
			 * // connection.setRequestProperty("Authorization"); // setRequestProperty is
			 * key with value
			 * connection.setRequestProperty("WWW-Authenticate", getAuthenticateHeader());
			 * // setRequestProperty is key with value
			 * 
			 * connection.setUseCaches(false); // always try to get a fresh copy
			 * connection.setDoOutput(true); // use the URL connection for output,
			 * DataOutputStream wr2 = new DataOutputStream(connection.getOutputStream());
			 * wr2.write(urlParameters.getBytes()); // write number byte to the
			 * OutputStream.
			 * wr2.close();
			 * if (connection.getResponseCode() == 401) {
			 * BufferedReader br2 = null;
			 * br2 = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
			 * String strCurrentLine;
			 * while ((strCurrentLine = br2.readLine()) != null) {
			 * logger.trace("BufferedReader1=" + strCurrentLine );
			 * }
			 * } else {
			 * InputStream is2 = connection.getInputStream();
			 * BufferedReader rd2 = new BufferedReader(new InputStreamReader(is2));
			 * String line2;
			 * while ((line2 = rd2.readLine()) != null) {
			 * logger.trace("BufferedReader2=" + line2 );
			 * }
			 * rd2.close();
			 * }
			 * // - eof insert to check for 401 body
			 */

			/*
			 * connection.setRequestMethod("POST"); // GET POST HEAD OPTIONS PUT DELETE
			 * TRACE
			 * connection.setRequestProperty("Connection", "Keep-Alive"); //
			 * https://docs.oracle.com/javase/8/docs/api/java/net/URLConnection.html#
			 * setRequestProperty-java.lang.String-java.lang.String-
			 * connection.setRequestProperty("Content-Type",
			 * "application/x-www-form-urlencoded");
			 * connection.setRequestProperty("Content-Length",
			 * Integer.toString(urlParameters.getBytes().length));
			 */

			String userpass = username + ":" + password;
			logger.trace("urlParameters=" + urlParameters + ", userpass=", userpass); // 15okt24 Ptro debug why we
																						// cannot connect edimax

			// String userpass = username + ":edimax001"; // 15okt24 ptro force password,
			// now fixed as we solved "== null" by equals()

			/*
			 * String credentials = "ptt" + ":" + "ptt123";
			 * String encoding = Base64Converter.encode(credentials.getBytes("UTF-8"));
			 * URLConnection uc = url.openConnection();
			 * uc.setRequestProperty("Authorization", String.format("Basic %s", encoding));
			 */

//  . . . . . . . . . first connection		Basic

			// Digest authentication is far more complex than just sending username:password
			// String basicAuth = "Basic "
			String basicAuth = "Basic "	+ DatatypeConverter.printBase64Binary(userpass.getBytes());
			// basicAuth = "Basic " + userpass; // base64-user-pass // testing
			logger.trace("basicAuth=" + userpass + ", cod64=" + basicAuth); // 15okt24 Ptro debug why we cannot connect edimax

			// connection.setRequestMethod("POST"); // GET POST HEAD OPTIONS PUT DELETE TRACE
			// connection.setRequestMethod("GET"); // GET POST HEAD OPTIONS PUT DELETE TRACE
			// connection.setRequestMethod("HEAD"); // not intrested in get input
			// connection.setRequestProperty("Connection", "keep-alive");
			// logger.trace("Connection keep-alive  586") ; // 15okt24 Ptro debug why we cannot connect edimax

		//	connection.setRequestProperty("Connection", "Keep-Alive"); // https://docs.oracle.com/javase/8/docs/api/java/net/URLConnection.html#setRequestProperty-java.lang.String-java.lang.String-
			connection.setRequestProperty("Accept", "*/*");
			connection.setRequestProperty("Content-Length", "0" ) ; // HttpClient add Content-Length only for non-empty bodies.

		//	connection.setRequestProperty("Content-Length",	Integer.toString(urlParameters.getBytes().length));
								
			connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			connection.setRequestProperty("Authorization", basicAuth); //  (ignore as we will not do this here)
			logger.trace("612 setRequestProperty(Authorization =" + basicAuth) ; // 15okt24 Ptro debug why we cannot connect edimax
			connection.setRequestMethod("POST"); // not interested yet in any input, so content/length = 0
			connection.setUseCaches(false); // always try to get a fresh copy
			connection.setDoOutput(true); // use the URL connection for output, implies POST

			logger.trace("HttpURLConnection 600=" + connection) ; // 15okt24 Ptro debug why we cannot connect edimax

			DataOutputStream wr1 = new DataOutputStream( connection.getOutputStream() );	// this establish connection, header exchange
			logger.trace("(warning1a) 613 writing wr1 data:" + urlParameters );
			wr1.write(0); // empty body
			wr1.flush();
			wr1.close();
			connection.getOutputStream().close();


			// connection.setUseCaches(false); // always try to get a fresh copy
			//connection.setUseCaches(true); // always try to get a fresh copy


			// HttpURLConnection=sun.net.www.protocol.http.HttpURLConnection:http://192.168.1.114:10000/smartplug.cgi

			// Send request
		//	DataOutputStream wr = new DataOutputStream(connection.getOutputStream());	// this establish connection, header exchange


				// HttpURLConnection java.lang.IllegalStateException: connect in progress
				// HttpURLConnection java.lang.IllegalStateException: Already connected
				// this documents the proces where connection and requests are flowing...
				// [https://stackoverflow.com/questions/10116961/can-you-explain-the-httpurlconnection-connection-process]

				// timer options to measure bocking
				// long start = System.currentTimeMillis();
				// logger.trace("Time so far = " + new Long(System.currentTimeMillis() - start)
				// );
				// run the above example code here
				// log.info("Total time to send/receive data = " + new
				// Long(System.currentTimeMillis() - start) );

			logger.trace("wr.write(urlParameters.getBytes())=null" );

			// wr.write(urlParameters.getBytes()); // write number byte to the OutputStream.
			// logger.trace("step1 wr.write(urlParameters.getBytes()); done"); // 15okt24
			// Ptro debug why we cannot connect

			// write empty
			// to try using [https://stackoverflow.com/questions/8722878/urljava-io-ioexception-server-returned-http-response-code-411-in-java]
		// wr.write("{}".getBytes()); // write number byte to the OutputStream.
		// wr.write(urlParameters.getBytes());		// write the body

		// wr.close();

			// logger.trace("step1 wr.write space; done" ); // 15okt24 Ptro debug why we
			// cannot connect
		// logger.trace("step1 no write of data, connections remains active"); // 15okt24 Ptro debug why we cannot
																				// connect

			// wr.close(); delay close after final, may fail response ..... 17okt24
			// logger.trace("step1 wr.close(); closed" ); // 15okt24 Ptro debug why we
			// cannot connect edimax

			// 2024-10-15 21:41:36.035 [DEBUG] [inding.edimax.internal.EdimaxBinding]
			// HTTPSend- wr.write(urlParameters.getBytes()); done & closed
			// followed by our finnally and followed by ioException as catched in
			// EdimaxBinding.java

			// note: on curl we get back 401: < WWW-Authenticate: Digest realm="SP1101W",
			// nonce="1845ce45bd3a5dac6fe01105c63bc416", qop="auth"

			// check response
			// 2024-10-15 22:06:17.831 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
			// responseCode =401
			// see for all possible codes:
			// [https://docs.oracle.com/javase/8/docs/api/java/net/HttpURLConnection.html]

			logger.trace("1responseCode1    =" + connection.getResponseCode()); // 15okt24 Ptro debug why we cannot
			logger.trace("1responseMessage1 =" + connection.getResponseMessage()); // 15okt24 Ptro debug why we cannot

			/* cannot write if doOutput = false
				DataOutputStream wr0 = new DataOutputStream( connection.getOutputStream() );	// this establish connection, header exchange
				logger.trace("(warning1a) 665 writing wr0 data: {}" );
				wr0.write("{}".getBytes());
				wr0.flush();
				wr0.close();
				connection.getOutputStream().close();
			*/

			// for getHeaderFields()
			// read
			// [https://www.codejava.net/java-se/networking/how-to-use-java-urlconnection-and-httpurlconnection]
			logger.trace("1getHeaderFields()=" + connection.getHeaderFields());
				/* 
				header info

					// 2024-10-16 01:21:16.210 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
					// getHeaderFields()={null=[HTTP/1.1 401 Unauthorized],
					// Server=[lighttpd/1.4.31-devel-325M],
					// WWW-Authenticate=[Digest realm="SP1101W",
					// nonce="4eefd0c45d40d370f4fe0b3e9d225057", qop="auth"],
					// Content-Length=[333],
					// Date=[Wed, 16 Oct 2024 00:21:25 GMT],
					// Content-Type=[text/html]}
				*/

			if (connection.getResponseCode() == 401) {
				logger.debug("1getHeaderFields(WWW-Authenticate)=" + connection.getHeaderField("WWW-Authenticate"));
				HashMap<String, String> headerValues1 = parseHeader(connection.getHeaderField("WWW-Authenticate"));
				BufferedReader br1 = null;
				logger.trace("Get errors from errorstream1"); // 15okt24 Ptro debug why we cannot
				if ( connection.getRequestMethod() != "HEAD") {  // get body contents
					br1 = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
					String strCurrentLine1;
					while ((strCurrentLine1 = br1.readLine()) != null) {
						logger.trace("errorstream1 =" + strCurrentLine1);
						/* 
						message info
		
							* 2024-10-15 22:28:59.862 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* responseMessage =Unauthorized
							* 2024-10-15 22:28:59.863 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream =<?xml version="1.0" encoding="iso-8859-1"?>
							* 2024-10-15 22:28:59.864 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream =<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
							* 2024-10-15 22:28:59.864 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream = "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
							* 2024-10-15 22:28:59.866 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream =<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en"
							* lang="en">
							* 2024-10-15 22:28:59.867 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream = <head>
							* 2024-10-15 22:28:59.868 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream = <title>401 - Unauthorized</title>
							* 2024-10-15 22:28:59.869 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream = </head>
							* 2024-10-15 22:28:59.870 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream = <body>
							* 2024-10-15 22:28:59.871 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream = <h1></h1>
							* 2024-10-15 22:28:59.872 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream = </body>
							* 2024-10-15 22:28:59.872 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
							* errorstream =</html>
							*/
					}
					br1.close();		// to reuse socket
					connection.getErrorStream().close();
					logger.trace("736 connection.getErrorStream().close();");
				} else {
					logger.trace(" (warning) 737 connection.getRequestMethod()=" + connection.getRequestMethod() ); // 15okt24 Ptro debug why we cannot
				}
			}
			StringBuilder response1 = new StringBuilder();
			if (connection.getResponseCode() == 200) {			// this shoud obviously not the normal case at first call
				InputStream is1 = connection.getInputStream();	// this produces an IOException if we have errors
																// if not connected, or the socket input has been shut down
				logger.trace("Process InputStream is1 = connection1.getInputStream()"); // 15okt24 Ptro debug why we cannot
				BufferedReader rd1 = new BufferedReader(new InputStreamReader(is1));
				String line1;
				while ((line1 = rd1.readLine()) != null) {
					response1.append(line1);
					response1.append('\r');
				}
				rd1.close();	// ensure input buffer is closed
				if (response1 != null) {
					logger.warn("edimax returned response1=" + response1.toString()); // 15okt24 Ptro debug why we cannot connect edimax
					return response1.toString();
				}
			}

			/* do no execute
				InputStream is1b = connection.getInputStream(); // this produces an IOException if we have conenction errors
					// if not connected, or the socket input has been shut down
					logger.trace("Process InputStream is1 = connection1.getInputStream()"); // 15okt24 Ptro debug why we cannot
					BufferedReader rd1b = new BufferedReader(new InputStreamReader(is1b));
					StringBuilder response1b = new StringBuilder();
					String line1b;
					while ((line1b = rd1b.readLine()) != null) {
						logger.trace("edimax read input buffer=" + line1b );
					}
					rd1b.close();
				connection.getInputStream().close();
			*/

		// sof==digest=================================================================================================================
			//
			// routine to culculate and do digest authentication
			//
				// logger.trace("(warning check) calculateNonce() to md5=" + calculateMd5(calculateNonce("edimax001"))); // md5=4817E5892BF8AB093A33460D892B8FF9
				// (warning check) calculateNonce() to md5=D046F8A4A0F387C452548E9629BA9AD5
					// convert string to byte array
					// byte[] b = string.getBytes();
					// byte[] b = string.getBytes(Charset.forName("UTF-8"));
					// byte[] b = string.getBytes(StandardCharsets.UTF_8); // Java 7+ only

			logger.debug("getHeaderFields(WWW-Authenticate)=" + connection.getHeaderField("WWW-Authenticate"));
					// getHeaderFields(WWW-Authenticate)=Digest realm="SP1101W",
					// nonce="431599ad5b6647f587b7cadeea9d20ef", qop="auth"
					// getHeaderFields(WWW-Authenticate)=Digest realm="SP1101W",
					// nonce="2e34e0968f6ca4116c55db0669b6accc", qop="auth"

					// see for inspiration:
					// [https://stackoverflow.com/questions/4278917/digest-authentication-using-urlconnection]
					// In the this is working using HttpClient. Much simpler and easier!

			// not sure if we can access a reused connection
			HashMap<String, String> headerValues2 = parseHeader(connection.getHeaderField("WWW-Authenticate"));
			realm = headerValues2.get("realm");		// server must be there
			nonce = headerValues2.get("nonce");		// server must be there
			String qop = headerValues2.get("qop");	// server "quality of protection" (qop)
			String header_uri = headerValues2.get("uri"); 	// possibly not supplied recreate smartplug_dir + smartplug_page
			String nonceCount = headerValues2.get("nc"); 	// possibly not supplied 00000001
			String clientNonce = headerValues2.get("cnonce"); 	// possibly not supplied wil generate one
			String headerMD5  = headerValues2.get("algorithm"); // possibly not supplied MD5
			logger.debug("(warning display1) getHeaderFields parsed realm=" + realm + 
						", qop=" + qop +
						", uri=" + header_uri + 
						", nc=" + nonceCount + 
						", algorithm=" + headerMD5 + 
						", cnonce=" + clientNonce );
			// (warning display2) realm=SP1101W, uri=/smartplug.cgi, qop=auth
			// ha1=0E823520DA1E186D20289C3240DED122,
			// ha2=E92F798768F685BFEA96BDAB585D8088,
			// response=ABF7D74ABBDFBD2FCE8CBE18A179950C

			// if String is null, then calling ...equals(null) will fail with a
			// NullPointerException
			if (!(header_uri != null)) {
				header_uri = "/"+ smartplug_dir + smartplug_page;		// hceck if edimax returns header
			}
			if (!(nonceCount != null)) {
				nonceCount = "00000001";
			}
			if (!(clientNonce != null)) {
				// clientNonce = "001NzljODJlZDgyYzJkNjY2YWY4YWQ5MGM2ZDkyNmM5N";
				clientNonce = "mynonce=" + nonce;		// prevent caching stattic value by taking a unique one
			}
			if (!(headerMD5 != null)) {
				nonceCount = "MD5";
			}

			// read rfc [https://datatracker.ietf.org/doc/html/rfc2617#section-3.2.2]
			String ha1 = calculateMd5(username + ":" + realm + ":" + password); // get MD5 code
			String ha2 = calculateMd5("POST" + ":" + header_uri); // get MD5 code
			String serverResponse = calculateMd5(
							ha1 + ":" + nonce + ":" + nonceCount + ":" + clientNonce + ":" + qop + ":" + ha2);
			// (warning display1) getHeaderFields parsed realm=SP1101W, qop=auth, uri=null,
			// nc=null, cnonce=null

			logger.trace("(warning display2) 793 calculateMd5 realm=" + realm + ", uri=" + header_uri + ", qop=" + qop
					+ "\n, ha1=" + ha1 + ", ha2=" + ha2 + ", response=" + serverResponse);

			/*
				// via import org.apache.commons.codec.digest.DigestUtils;
				String ha11 = MD5(username + ":" + realm + ":" + password); // get MD5 code
				String ha21 = MD5("POST" + ":" + "/smartplug.cgi"); // get MD5 code
				String serverResponse2 = MD5(ha11+":"+nonce+":"+nonceCount+":"+clientNonce+":"+qop+":"+ha21);
				logger.trace("(warning display3) 849 MD5 ha11=" + ha11 + 
						", ha21=" + ha21+ ", response=" + serverResponse2);
			*/			
		
			/*
					* sample from: https://en.wikipedia.org/wiki/Digest_access_authentication
					* Digest username="Mufasa",
					* realm="testrealm@host.com",
					* nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
					* uri="/dir/index.html",
					* qop=auth,
					* nc=00000001,
					* cnonce="0a4f113b",
					* response="6629fae49393a05397450978507c4ef1",
					* opaque="5ccc069c403ebaf9f0171e9517f40e41"
			*/

		/* Verify using theory on web and wireshark:
			Read: [https://www.hackingarticles.in/understanding-http-authentication-basic-digest/]
				We are providing “guest” as User Name and “guest” as a password.
				realm="Hacking Articles", nonce="58bac26865505", uri="/auth/02-2617.php", 
							opaque="8d8909139750c6bd277cfe1388314f48", qop=auth, nc=00000001,
							cnonce="72ae56dde9406045" , response="ac8e3ecd76d33dd482783b8a8b67d8c1",
				Hash1 Syntax=MD5(username:realm:password)
				hash1 =  md5(guest:Hacking Articles:guest)

				ha1: = 2c6165332ebd26709360786bafd2cd49
				ha2: = b6a6df472ee01a9dbccba5f5e6271ca8

				response Syntax =  MD5(Hash1:nonce:nonceCount:cnonce:qop:Hash2)
				response = MD5(2c6165332ebd26709360786bafd2cd49:58bac26865505:00000001:72ae56dde9406045:auth:b6a6df472ee01a9dbccba5f5e6271ca8)
				response = ac8e3ecd76d33dd482783b8a8b67d8c1

			from wire shark:
				WWW-Authenticate: Digest realm="SP1101W", nonce="08a9990384afffab9901d8564838ff6d", qop="auth"
				Hypertext Transfer Protocol
					POST /smartplug.cgi HTTP/1.1\r\n
						[Expert Info (Chat/Sequence): POST /smartplug.cgi HTTP/1.1\r\n]
						Request Method: POST
						Request URI: /smartplug.cgi
						Request Version: HTTP/1.1
					Host: 192.168.1.114:10000\r\n
					[truncated]Authorization: Digest username="admin", realm="SP1101W", nonce="08a9990384afffab9901d8564838ff6d", uri="/smartplug.cgi", cnonce="NzgwNzhjMTI1NTg2MmMwMjBkYTZlNzI2NmQ4OTNlZjU=", nc=00000001, qop=auth, 
								response="223b9d11aee0f0597

						ha1 --> admin:SP1101W:edimax001		0e823520da1e186d20289c3240ded122
						ha2: --> POST:/smartplug.cgi		94c24a3d0a78134ef8e8f6bae1a1b4ed
						resp: Hash1:nonce:nonceCount:cnonce:qop:Hash2 --> 0e823520da1e186d20289c3240ded122:08a9990384afffab9901d8564838ff6d:00000001:NzgwNzhjMTI1NTg2MmMwMjBkYTZlNzI2NmQ4OTNlZjU=:auth:94c24a3d0a78134ef8e8f6bae1a1b4ed
						--> 223b9d11aee0f05972b1500c061f9810
		*/

		/* test verify using: [https://www.md5hashgenerator.com/]
			data:
				- (warning display2) 793 calculateMd5 realm=SP1101W, uri=/smartplug.cgi, qop=auth      
				up	, HA1=0E823520DA1E186D20289C3240DED122	admin:SP1101W+edimax001
				up	, HA2=94C24A3D0A78134EF8E8F6BAE1A1B4ED  POST:/smartplug.cgi
				low	, ha1=0e823520da1e186d20289c3240ded122
				low	, ha2=94c24a3d0a78134ef8e8f6bae1a1b4ed
					, RESPONSE=EF03D140DCE77148AB062C55E472E858
					, response=ef03d140dce77148ab062c55e472e858

				Created digestAuth=Digest username="admin", realm="SP1101W", nonce="3e22ebc92f48ab4fdef128afd195c2fc", uri="/smartplug.cgi", 
				nc=00000001, qop=auth, cnonce="001NzljODJlZDgyYzJkNjY2YWY4YWQ5MGM2ZDkyNmM5N", response="EF03D140DCE77148AB062C55E472E858
			String ha1 = calculateMd5(username + ":" + realm + ":" + password); // get MD5 code
				ha1: admin:SP1101W:edimax001		--> 0E823520DA1E186D20289C3240DED122
			String ha2 = calculateMd5("POST" + ":" + header_uri); // get MD5 code
				ha2: POST:/smartplug.cgi			--> 94C24A3D0A78134EF8E8F6BAE1A1B4ED
			String serverResponse = calculateMd5(
				SR= 0E823520DA1E186D20289C3240DED122:3e22ebc92f48ab4fdef128afd195c2fc:00000001:001NzljODJlZDgyYzJkNjY2YWY4YWQ5MGM2ZDkyNmM5N:auth:94C24A3D0A78134EF8E8F6BAE1A1B4ED
					-->	EF03D140DCE77148AB062C55E472E858
				sr= 0e823520da1e186d20289c3240ded122:3e22ebc92f48ab4fdef128afd195c2fc:00000001:001NzljODJlZDgyYzJkNjY2YWY4YWQ5MGM2ZDkyNmM5N:auth:94c24a3d0a78134ef8e8f6bae1a1b4ed
					-->	b96673686fe87cb9424bcfcd8bd05d56

			test verify algori
				curl1:
					A1 = unq(username-value) : unq(realm-value) : passwd
					A2 = Method : digest-uri-value
					server = ha1 : digest->nonce : digest->nc : digest->cnonce : digest->qop : ha2 );

					Authorization: Digest username="admin", realm="SP1101W", 
					nonce="6482369cfbede534d670f1bc1da2c9b8", uri="/smartplug.cgi", 
					cnonce="ZGU5Y2M4MzM0MDMwZTQ1MTg4MTg2MmJjNGYxYTY4NTY=", 
					nc=00000001, qop=auth, response="f3513518a16ed451e63b1c66e60199cc"

					ha1: admin:SP1101W:edimax001	--> 0e823520da1e186d20289c3240ded122
					ha2: POST:/smartplug.cgi		--> 94c24a3d0a78134ef8e8f6bae1a1b4ed
					sr ha1:nonce:nc:cnonce:qop:ha2	--> f3513518a16ed451e63b1c66e60199cc
						0e823520da1e186d20289c3240ded122:6482369cfbede534d670f1bc1da2c9b8:00000001:ZGU5Y2M4MzM0MDMwZTQ1MTg4MTg2MmJjNGYxYTY4NTY=:auth:94c24a3d0a78134ef8e8f6bae1a1b4ed

					n/a, we have auth test2 response = MD5(HA1:nonce:HA2)
									0e823520da1e186d20289c3240ded122:6482369cfbede534d670f1bc1da2c9b8:94c24a3d0a78134ef8e8f6bae1a1b4ed
									-\-> 3785d3a44426fcbf0629e2385fcaf3ad
				curl2:
					* Server auth using Digest with user 'admin'
					> POST /smartplug.cgi HTTP/1.1
					> Host: 192.168.1.114:10000
					> Authorization: Digest username="admin", realm="SP1101W", nonce="6482369cfbede534d670f1bc1da2c9b8", uri="/smartplug.cgi", cnonce="ZGU5Y2M4MzM0MDMwZTQ1MTg4MTg2MmJjNGYxYTY4NTY=", nc=00000001, qop=auth, response="f3513518a16ed451e63b1c66e60199cc"
						0e823520da1e186d20289c3240ded122:6482369cfbede534d670f1bc1da2c9b8:00000001:ZGU5Y2M4MzM0MDMwZTQ1MTg4MTg2MmJjNGYxYTY4NTY=:auth:94c24a3d0a78134ef8e8f6bae1a1b4ed
					--> f3513518a16ed451e63b1c66e60199cc
				curl3:
					WWW-Authenticate: Digest realm="SP1101W", nonce="fb05972e12ea53d149dbb6b44622e4d9", qop="auth"
        			Request Method: POST Request URI: /smartplug.cgi
     				[truncated]Authorization: Digest username="admin", realm="SP1101W", 
					 		nonce="fb05972e12ea53d149dbb6b44622e4d9", uri="/smartplug.cgi", 
							cnonce="M2VjZGQ4MTYzOGY2OTkxMDdlZTY5MzMyOThiNjFjN2Y=", nc=00000001, 
							qop=auth, response="ace582b9fabc92f25.....truncated
					check Form URL Encoded: application/x-www-form-urlencoded
						ha1 -->  admin:SP1101W:edimax001	0e823520da1e186d20289c3240ded122
						ha2: --> POST:/smartplug.cgi		94c24a3d0a78134ef8e8f6bae1a1b4ed
						response Syntax =  MD5(Hash1:nonce:nonceCount:cnonce:qop:Hash2)
							0e823520da1e186d20289c3240ded122:fb05972e12ea53d149dbb6b44622e4d9:
							00000001:M2VjZGQ4MTYzOGY2OTkxMDdlZTY5MzMyOThiNjFjN2Y=:
							auth:94c24a3d0a78134ef8e8f6bae1a1b4ed
					response= ace582b9fabc92f2571ae49f920ebb53

			Our program is identical:
				warning display2) 793 calculateMd5 realm=SP1101W, uri=/smartplug.cgi, qop=auth 
					ha1=0E823520DA1E186D20289C3240DED122, 
					ha2=94C24A3D0A78134EF8E8F6BAE1A1B4ED, 
					response=EF03D140DCE77148AB062C55E472E858  (if uppercased)
		*/

			 // eof=digest==================================================================================================================


//  . . . . . . . . . first try connection		Digest	


			// int postDataLength = postData.length;
			// String request = "http://192.168.1.30:6262/api/values";
			// URL url = new URL(request);

			// connection.disconnect(); //
			// https://docs.oracle.com/javase/8/docs/api/java/net/URLConnection.html

			logger.trace("Initialize POST2 986");
			// connection = (HttpURLConnection) new URL(complete).openConnection();
			// URL url2 = new URL(complete);
			// connection = (HttpURLConnection) url2.openConnection(); // fieldtype java.net.HttpURLConnection; -->
			// curl:
				// > Authorization: Digest 
				//	username="admin", 
				//	realm="SP1101W", 
				//	nonce="a7837d44d1c47cd5fd4a9c06c7ce0734", 
				//	uri="/smartplug.cgi", 
				//	cnonce="NzczMjVkZjExYWEzMzg0MWE5MzExMWNkOGEzYTM2NjE=", 
				//	nc=00000001, qop=auth, 
				//	response="4d0d9fc615b7cc043102b9823bfe52c6"

			// 					" uri=\"/smartplug.cgi"		+ "\"," +
			// sequenced as stated in http_athu.c of lighthttp version /home/pafoxp/code_edimax/lighttpd-1.4.31
			String digestAuth = "Digest username=\"admin\"," +
					" realm=\"" + realm 		+ "\"," +
					" nonce=\"" + nonce 		+ "\"," +
					" uri=\"/" + smartplug_dir +  smartplug_page	+ "\"," +
					" algorithm=\"" + headerMD5	+ "\"," +
					" qop=" + qop 	 			+ 	","	+
					" cnonce=\"" + clientNonce 	+ "\"," +
					" nc=" + nonceCount 		+   "," +
					" response=\"" + serverResponse; 
					// + "\" ,opaque=\"" + calculateMd5(realm + nonce) + "\"";

			logger.debug("1010 Created digestAuth=" + digestAuth );

					// 2024-10-17 03:34:04.603 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
					// (warning display3)
					// digest=Digest username="admin", realm="SP1101W",
					// nonce ="6e44538ecc6668c5e83be896b591a99c", qop=auth, nc=00000001
					// cnonce="abcdefghijklmnopqrstuvwxyz",
					// response="325596E28391A107FDD87B5BA658DD4A", opaque="error"

					// wr.close();
					// logger.trace("step1 wr.close(); closed"); // 15okt24 Ptro debug why we cannot
					// connect edimax

			logger.trace("--> Initialize POST2 1023");

			// connection.setUseCaches(true); // already connected, once opened
	/*

			logger.trace("Initialize POST2 873");
			// -------------------------------------------------------------------------------------------------------------------------------
			//  [https://github.com/openjdk/jdk/blob/jdk-18%2B0/src/java.base/share/classes/sun/net/www/protocol/http/HttpURLConnection.java] 
			//		public void setRequestProperty(String key, String value) will always check on connected
			// -------------------------------------------------------------------------------------------------------------------------------
			connection.setRequestProperty("Authorization", digestAuth); // already connected, once opened

			logger.trace("Initialize POST2 875");
			connection.setRequestMethod("POST"); // GET POST HEAD OPTIONS PUT DELETE TRACE
			logger.trace("Initialize POST2 877");
			connection.setRequestProperty("Content-Length",	Integer.toString(urlParameters.getBytes().length));
			connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			connection.setDoOutput(true); // use the URL connection for output
			DataOutputStream wr1 = new DataOutputStream( connection.getOutputStream() );	// this establish connection, header exchange
			logger.trace("(warning1a) 882 writing wr1 data:" + urlParameters );
			wr1.write((urlParameters).getBytes());
			wr1.flush();
			wr1.close();
			connection.getOutputStream().close();
			
			logger.trace("(warning1a) 886 data written: connection.getResponseCode()=" + connection.getResponseCode());
			if (connection.getResponseCode() == 401 ) {
				BufferedReader br1a = null;
				br1a = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
				String strCurrentLine1a;
				while ((strCurrentLine1a = br1a.readLine()) != null) {
					logger.trace("Process errorstream1a =" + strCurrentLine1a );
				}	
			}
			if (connection.getResponseCode() == 200 ) {
				InputStream is1a = connection.getInputStream(); // this produces an IOException
				logger.trace("Process InputStream is1a = connection.getInputStream()"); // 15okt24 Ptro debug why we cannot
				BufferedReader rd1a = new BufferedReader(new InputStreamReader(is1a));
				String line1a;
				while ((line1a = rd1a.readLine()) != null) {
					response.append(line1a);
					response.append('\r');
				}
				rd1a.close();
				logger.trace("edimax returned1=" + response.toString()); // 15okt24 Ptro debug why we cannot connect edimax
				return response.toString();
			}
			
	*/
								
//  . . . . . . . . . second connection		Digest on new socket	

			// connection2 = (HttpURLConnection) url2.openConnection(); // fieldtype java.net.HttpURLConnection; -->
			connection.disconnect();
			URL url2 = new URL(complete);		// will likely create a new connection with a different digest
			connection2 = (HttpURLConnection) url2.openConnection(); // fieldtype java.net.HttpURLConnection; -->
			logger.trace("1098 2responseLog2a url2=" + url2 ); // 15okt24 Ptro debug why we cannot
		//	logger.trace("2responseCode2a    =" + connection2.getResponseCode()); // 15okt24 Ptro debug why we cannot
		//	logger.trace("2responseMessage2a =" + connection2.getResponseMessage()); // 15okt24 Ptro debug why we cannot
			
			/* from: [https://gist.github.com/habitaso/ec25722e9c2796122bf40efaf38c6552]
					// connection.setRequestProperty("Authorization",
					"Digest username="+user+
					", realm="+realm+
					", nonce="+nonce+
					", uri="+uri+
					", algorithm=MD5, response="+hx_response+
					", qop=auth, nc=00000001, cnonce="+cnonce );
			*/
			/*
			connection2.setRequestProperty("Authorization", 
					"Digest username="+username		+
					", realm="+realm				+
					", nonce="+nonce				+
					", uri=/smartplug.cgi"			+
					", response="+serverResponse2	+
					", qop=auth, nc=00000001, cnonce="+clientNonce );
					//						", algorithm=MD5, 
			*/					
		
		//	logger.trace("2responseCode3    =" + connection2.getResponseCode()); // 15okt24 Ptro debug why we cannot
		//	logger.trace("2responseMessage3 =" + connection2.getResponseMessage()); // 15okt24 Ptro debug why we cannot

		//	connection2.setRequestProperty("Connection", "Keep-Alive"); // https://docs.oracle.com/javase/8/docs/api/java/net/URLConnection.html#setRequestProperty-java.lang.String-java.lang.String-
			connection2.setRequestProperty("Accept", "*/*");
			connection2.setRequestMethod("POST"); // GET POST HEAD OPTIONS PUT DELETE TRACE
			logger.trace("2responseLog4 Accept and POST properties set." ); // 15okt24 Ptro debug why we cannot   

			logger.trace("warning step2a setRequestProperty(Authorization)=" + digestAuth ); // 15okt24 Ptro debug why we cannot connect			
			connection2.setRequestProperty("Authorization", digestAuth); // stream must be closed else we got an already conencted					
				// this fails here as: 
				// 	java.lang.IllegalStateException: Already connected 
				// connection.addRequestProperty("Authorization", digestAuth);
			logger.trace("1124 warning step2b setRequestProperty(Authorization)=" + digestAuth ); // 15okt24 Ptro debug why we cannot connect


		//	logger.trace("responseCode4    =" + connection.getResponseCode()); // 15okt24 Ptro debug why we cannot
		//	logger.trace("responseMessage4 =" + connection.getResponseMessage()); // 15okt24 Ptro debug why we cannot

			connection2.setRequestProperty("Content-Length",	Integer.toString(urlParameters.getBytes().length));
			connection2.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			// post.setHeader("Accept", "application/json");		// ? from a sample
			// post.setHeader("Content-Type", "application/json");	// ? from a sample 
			logger.trace("connection Content-Length=" + Integer.toString((urlParameters.getBytes().length) ) );  // check for legth as we go an 411

				// 2024-10-17 05:44:38.859 [DEBUG] [inding.edimax.internal.EdimaxBinding] - Content-Length=122 

			// connection2 = (HttpURLConnection) url2.openConnection() ; // fieldtype java.net.HttpURLConnection; -->
		//	connection2.connect();
		//	logger.trace("responseCode5    =" + connection2.getResponseCode()); // 15okt24 Ptro debug why we cannot
		//	logger.trace("responseMessage5 =" + connection2.getResponseMessage()); // 15okt24 Ptro debug why we cannot

			connection2.setUseCaches(false); // always try to get a fresh copy
			connection2.setDoOutput(true); // use the URL connection for output,
		//	logger.trace("2responseCode6    =" + connection2.getResponseCode()); // 15okt24 Ptro debug why we cannot
		//	logger.trace("2responseMessage6 =" + connection2.getResponseMessage()); // 15okt24 Ptro debug why we cannot
		//	logger.trace("2getHeaderFields(WWW-Authenticate)=" + connection2.getHeaderField("WWW-Authenticate")); // will close for read
			
			// logger.trace("connection urlParameters=" + urlParameters + ".");  // check for length as we got an 411 response
			    // text length = 120 
				//	<?xml version="1.0" encoding="UTF8"?>
				//	<SMARTPLUG id="edimax"><CMD id="get"><Device.System.Power.State/></CMD></SMARTPLUG>

				// DataOutputStream wr2 = new DataOutputStream(connection.getOutputStream());
				// wr2.write((urlParameters+"{}").getBytes());
				// wr = new DataOutputStream(connection.getOutputStream());

			logger.trace("wr2.write(urlParameters.getBytes())=" + urlParameters + ", getDoOutput()=" + connection2.getDoOutput() ) ; 
			DataOutputStream wr = new DataOutputStream( connection2.getOutputStream() );	// this establish connection, header exchange
			logger.trace("responseCode7    =" + connection2.getResponseCode()); // 15okt24 Ptro debug why we cannot
			logger.trace("responseMessage7 =" + connection2.getResponseMessage()); // 15okt24 Ptro debug why we cannot

			wr.write((urlParameters).getBytes());
			logger.trace("step2 wr.write(urlParameters.getBytes()); >"+ urlParameters + "< done"); // 15okt24 Ptro debug why we cannot connect

			logger.trace("2responseCode8    =" + connection2.getResponseCode()); // 15okt24 Ptro debug why we cannot
			logger.trace("2responseMessage8 =" + connection2.getResponseMessage()); // 15okt24 Ptro debug why we cannot

			wr.flush();
			wr.close();
			// we now got: 
			logger.trace("step3 wr.close()"); // 15okt24 Ptro debug why we cannot connect edimax

			logger.trace("responseCode9    =" + connection2.getResponseCode()); // 15okt24 Ptro debug why we cannot
			logger.trace("responseMessage9 =" + connection2.getResponseMessage()); // 15okt24 Ptro debug why we cannot
			// 2024-10-17 19:08:47.179 [DEBUG] [inding.edimax.internal.EdimaxBinding] - responseCode2    =400 
			// 2024-10-17 19:08:47.202 [DEBUG] [inding.edimax.internal.EdimaxBinding] - responseMessage2 =Bad Request 


			/*
			 * 
			 * String method = request.getMethod(); // ??
			 * // getHeaderFields(WWW-Authenticate)=Digest realm="SP1101W",
			 * nonce="e8fe8401d62aae86f8a6de1202fcbf4c", qop="auth"
			 * 
			 * // md5hex Calculates the MD5 digest and returns the value as a 32 character
			 * hexadecimal string.
			 * 
			 * String ha1 = DigestUtils.md5Hex(userName + ":" + realm + ":" + password);
			 * String qop = headerValues.get("qop"); // "quality of protection" (qop)
			 * String ha2;
			 * String reqURI = headerValues.get("uri");
			 * //
			 * // if (!StringUtils.isBlank(qop) && qop.equals("auth-int")) {
			 * // String entityBodyMd5 = DigestUtils.md5Hex(requestBody);
			 * // ha2 = DigestUtils.md5Hex(method + ":" + reqURI + ":" + entityBodyMd5);
			 * // } else {
			 * //
			 * // ha2 = DigestUtils.md5Hex(method + ":" + reqURI);
			 * // }
			 * ha2 = DigestUtils.md5Hex(method + ":" + reqURI);
			 * String serverResponse
			 * 
			 */
			// eof
			// ===================================================================================================================

			// 2024-10-16 00:51:58.998 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
			// getHeaderFields()={null=[HTTP/1.1 401 Unauthorized],
			// Server=[lighttpd/1.4.31-devel-325M],
			// WWW-Authenticate=[Digest realm="SP1101W",
			// nonce="a3ab1746c7dd6c9c41d905b1f635abec", qop="auth"],
			// Content-Length=[333],
			// Date=[Tue, 15 Oct 2024 23:52:09 GMT],
			// Content-Type=[text/html]}

			// not we have a faulty/error , we must retrieve the stream by , read
			// [https://stackoverflow.com/questions/25011927/how-to-get-response-body-using-httpurlconnection-when-code-other-than-2xx-is-re]

			logger.trace("before  InputStream is = connection2.getInputStream():" + connection2 ); // 15okt24 Ptro debug why we cannot
			if (connection2.getResponseCode() == 401 ) {
				logger.debug("Process Errorstream2 getResponseCode()=" + connection2.getResponseCode() ); // 15okt24 Ptro debug why we cannot
				BufferedReader br2 = null;
				br2 = new BufferedReader(new InputStreamReader(connection2.getErrorStream()));
				String strCurrentLine2;
				while ((strCurrentLine2 = br2.readLine()) != null) {
					logger.trace("Process errorstream2 =" + strCurrentLine2);
					// Get Response
				}	
				br2.close();
				connection2.getErrorStream().close();
			}
			if (connection2.getResponseCode() == 200 ) {
				InputStream is2 = connection2.getInputStream(); // this produces an IOException
																// if not connected, or the socket input has been shut down
				logger.debug("Process InputStream is2 = connection.getInputStream()"); // 15okt24 Ptro debug why we cannot
				BufferedReader rd2 = new BufferedReader(new InputStreamReader(is2));
				String line;
				while ((line = rd2.readLine()) != null) {
					response.append(line);
					response.append('\r');
				}
				rd2.close();
				logger.trace("1250 afer InputStream is2 = connection2.getInputStream()"); // 15okt24 Ptro debug why we cannot	
			}	

			if ( !(response != null) || response.toString().length() == 0 ) {
				logger.debug("1087 creating a dummy ON response:"); // 15okt24 Ptro debug why we cannot	
				response.append("<?xml version=\"1.0\" encoding=\"UTF8\"?>");
				response.append("<SMARTPLUG id=\"edimax\">  "); 
				response.append("  <CMD id=\"get\">") ;
				response.append("<Device.System.Power.State>ON</Device.System.Power.State>");
				response.append("  </CMD>");
				response.append("</SMARTPLUG>");
				response.append('\r');
			}
			logger.trace("1098 edimax begin returned" );
			logger.trace("1099 edimax begin returned=" + response.toString().length() ); 
			logger.debug("1100 edimax returned=" + response.toString() + ", len=" + response.toString().length() );
			return response.toString();

		} finally { // The finally block is always run after the try block ends
			if (connection != null) {
				// 2024-10-15 21:41:36.064 [DEBUG] [inding.edimax.internal.EdimaxBinding]
				// HTTPSend- executePost: try finally connection.disconnect()
				// followed by ioException as catched in EdimaxBinding.java
				logger.trace("executePost: try finally connection.disconnect() "); // 15okt24 Ptro debug why we cannot
				connection.disconnect();
			}
			if (connection2 != null) {
				// 2024-10-15 21:41:36.064 [DEBUG] [inding.edimax.internal.EdimaxBinding]
				// HTTPSend- executePost: try finally connection.disconnect()
				// followed by ioException as catched in EdimaxBinding.java
				logger.trace("executePost: try finally connection2.disconnect() "); // 15okt24 Ptro debug why we cannot
				connection2.disconnect();
			}

		}
	}

}
