/**
 * Copyright (c) 2010-2015, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.edimax.internal;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.net.HttpURLConnection;		// https://docs.oracle.com/javase/8/docs/api/java/net/HttpURLConnection.html
import java.net.URL;

import javax.xml.bind.DatatypeConverter;

import org.openhab.binding.edimax.internal.commands.GetCurrent;
import org.openhab.binding.edimax.internal.commands.GetMAC;
import org.openhab.binding.edimax.internal.commands.GetPower;
import org.openhab.binding.edimax.internal.commands.GetState;
import org.openhab.binding.edimax.internal.commands.SetState;



import org.slf4j.Logger;				// 15okt24 Ptro checkout URL communication
import org.slf4j.LoggerFactory;			// 15okt24 Ptro checkout URL communication
import java.util.Date; 					// 15okt24 Ptro checkout URL Authentication nonce
import java.util.Random; 				// 15okt24 Ptro checkout URL Authentication nonce
// import org.apache.commons.codec.digest.DigestUtils; // 15okt24 Ptro checkout URL Authentication nonce
import java.security.MessageDigest;		// 15okt24 Ptro checkout URL Authentication nonce		
import java.security.NoSuchAlgorithmException; // 15okt24 Ptro checkout URL Authentication nonce		
// import java.security.*;
import org.apache.commons.lang.StringUtils;	// 15okt24 Ptro checkout URL Authentication nonce
import java.io.UnsupportedEncodingException;

import java.util.HashMap; 			// 15okt24 Ptro checkout URL Authentication keying Authentication headers


/**
 * Sends commands and returns responses for the edimax device, using it's http
 * interface.
 * 
 * @author Heinz
 *
 */
public class HTTPSend {

	/**
	 * Logger.  15okt24 Ptro checkout URL communication
	 */
	private static final Logger logger = LoggerFactory
			.getLogger(EdimaxBinding.class);


	public static final String XML_HEADER = "<?xml version=\"1.0\" encoding=\"UTF8\"?>\r\n";

	private static final String defaultUser = "admin";
	// private static final String defaultPassword = "1234";
	private static final String defaultPassword = "edimax001";		// 15okt24 ptro force password

	protected static final int PORT = 10000;

	private static String completeURL(String anIp) {
		return "http://" + anIp;
	}

	private String password;

    private static String authMethod = "auth";		    // ptro 15okt24 for authentication
    private static String realm = "example.com";		// ptro 15okt24 for authentication
    // public  String nonce;						// ptro 15okt24 for authentication
    private static String nonce;						// ptro 15okt24 for authentication

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
	 *             (mac != null) { // found a device! Device d = new Device();
	 *             d.ip = portScanUsage.getIp(); d.mac = mac; discovered.add(d);
	 *             }
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
        nonce = calculateNonce();
        header += "Digest realm=\"" + realm + "\",";
        if (!StringUtils.isBlank(authMethod)) {
            header += "qop=" + authMethod + ",";
        }
        header += "nonce=\"" + nonce + "\",";
        header += "opaque=\"" + getOpaque(realm, nonce) + "\"";

        return header;
    }



    /** 15okt24 ptro
     * Convert a string representation of hexadecimal to a byte array.
     *
     * For example: String s = "00010203" returned byte array is {0x00, 0x01, 0x03}
     *
     * @param hex hex input string
     * @return byte array equivalent to hex string
     **/
    public static byte[] hexStringToByteArray(String hex) {
		// String commandString = baseString + rfAddress;
		// String encodedString = Base64.encodeBase64String(Utils.hexStringToByteArray(commandString));
        String s = hex.replace(" ", "");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
    private static final String HEXES = "0123456789ABCDEF";
    /** 15okt24 ptro
     * Convert a byte array to a string representation of hexadecimals.
     *
     * For example: byte array is {0x00, 0x01, 0x03} returned String s =
     * "00 01 02 03"
     *
     * @param raw byte array
     * @return String equivalent to hex string
     **/
    public static String getSpacedHex(byte[] raw) {
        if (raw == null) {
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
        if (raw == null) {
            return "";
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }

    /** 15okt24 ptro
     * Calculate the nonce based on fixed value 
     *
     * @return
     */
    // public String calculateNonce() {
    private static String calculateNonce() { 

	    try {
	        MessageDigest md5 = MessageDigest.getInstance("MD5");
			// return URLEncoder.encode(str, StandardCharsets.UTF_8.name());
            try {
	     		return new String(md5.digest(("testedimax001").getBytes("UTF-8")),"UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new UnsupportedOperationException("UTF-8 not supported");
            }
			// byte array tot string [https://www.geeksforgeeks.org/java-program-to-convert-byte-array-to-string/]
	    } catch (NoSuchAlgorithmException e) {
	        logger.error("This version of Java does not support MD5 hashing");
	        return "";
	    }
		/* 
		    Date d = new Date();
		    SimpleDateFormat f = new SimpleDateFormat("yyyy:MM:dd:hh:mm:ss");
		    String fmtDate = f.format(d);
		    Random rand = new Random(100000);
		    Integer randomInt = rand.nextInt();
		    return DigestUtils.md5Hex(fmtDate + randomInt.toString());
		*/
    }

    /**  15okt24 ptro
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
	// read: [https://stackoverflow.com/questions/415953/how-can-i-generate-an-md5-hash-in-java]

    public static byte[] md5(byte[] source) throws MiIoCryptoException {
        try {
            MessageDigest m = MessageDigest.getInstance("MD5");
            return m.digest(source);
        } catch (NoSuchAlgorithmException e) {
            throw new MiIoCryptoException(e.getMessage(), e);
        }
    }



	The compute the hash by doing one of:
		Feed the entire input as a byte[] and calculate the hash in one operation with md.digest(bytes).
		Feed the MessageDigest one byte[] chunk at a time by calling md.update(bytes). When you're done adding input bytes, calculate the hash with md.digest().
	The byte[] returned by md.digest() is the MD5 hash
	--------------------------------------------------------------
	import java.security.*;
	..
	byte[] bytesOfMessage = yourString.getBytes("UTF-8");

	MessageDigest md = MessageDigest.getInstance("MD5");
	byte[] theMD5digest = md.digest(bytesOfMessage);
	--------------------------------------------------------------

		protected String createResponse(String challenge) {
		    String handshake = challenge.concat("-").concat(config.getPassword());
		    MessageDigest md5;
		    try {
		        md5 = MessageDigest.getInstance("MD5");
		    } catch (NoSuchAlgorithmException e) {
		        logger.error("This version of Java does not support MD5 hashing");
		        return "";
		    }
		    byte[] handshakeHash;
		    try {
		        handshakeHash = md5.digest(handshake.getBytes("UTF-16LE"));
		    } catch (UnsupportedEncodingException e) {
		        logger.error("This version of Java does not understand UTF-16LE encoding");
		        return "";
		    }
		    String response = challenge.concat("-");
		    for (byte handshakeByte : handshakeHash) {
		        response = response.concat(String.format("%02x", handshakeByte));
		    }
		    return response;
		}
	*/

    // private String getOpaque(String domain, String nonce) {
    public static String getOpaque(String domain, String nonce) {
	    try {
	        MessageDigest md5 = MessageDigest.getInstance("MD5");
			// return new String( md5.digest( (domain+nonce).getBytes("UTF-8") ),"UTF-8" );
            try {
	     		return new String( md5.digest( (domain+nonce).getBytes("UTF-8") ),"UTF-8" );
            } catch (UnsupportedEncodingException e) {
                throw new UnsupportedOperationException("UTF-8 not supported");
            }
			// byte array tot string [https://www.geeksforgeeks.org/java-program-to-convert-byte-array-to-string/]
	    } catch (NoSuchAlgorithmException e) {
	        logger.error("This version of Java does not support MD5 hashing");
	        return "";
	    }
        // return DigestUtils.md5Hex(domain + nonce);
    }



	public static String executePost(String targetURL, int targetPort,
			String targetURlPost, String urlParameters, String username,
			String password) throws IOException {
		String complete = targetURL + ":" + targetPort + "/" + targetURlPost;

        logger.debug("complete=" + complete + ", urlParameters="+ urlParameters );		// 15okt24 Ptro debug why we cannot connect edimax
		// http://192.168.1.130:10000/smartplug.cgi  urlParameters=<?xml version="1.0" encoding="UTF8"?>
		//		<SMARTPLUG id="edimax"><CMD id="get"><Device.System.Power.State/></CMD></SMARTPLUG> 

		// get should return <SMARTPLUG id="edimax"> <CMD id="get"><Device.System.Power.State>ON</Device.System.Power.State> </CMD></SMARTPLUG>
        // hoeever we get a  HTTP/1.1 401 Unauthorized response body 
		HttpURLConnection connection = null;
		try {
			// Create connection  , read: [https://www.geeksforgeeks.org/how-to-use-httpurlconnection-for-sending-http-post-requests-in-java/]
			//   HttpURLConnection: GET, POST, PUT, and DELETE

			URL url = new URL(complete);
			connection = (HttpURLConnection) url.openConnection();		// fieldtype java.net.HttpURLConnection; --> HttpURLConnection

/* 			
	// does not work: java.io.IOException: Server returned HTTP response code: 400  (invalid request.... )
			// - sof insert to check for 401 body
			// connection.setRequestProperty("Authorization");			// setRequestProperty is key with value
			connection.setRequestProperty("WWW-Authenticate", getAuthenticateHeader());			// setRequestProperty is key with value

			connection.setUseCaches(false);		// always try to get a fresh copy 
			connection.setDoOutput(true);		// use the URL connection for output,
			DataOutputStream wr2 = new DataOutputStream(connection.getOutputStream());				
			wr2.write(urlParameters.getBytes());					// write number byte to the OutputStream.
			wr2.close();
            if (connection.getResponseCode() == 401) {
				BufferedReader br2 = null;
			    br2 = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
			    String strCurrentLine;
		        while ((strCurrentLine = br2.readLine()) != null) {
						logger.debug("BufferedReader1=" + strCurrentLine );
				}
			} else {
				InputStream is2 = connection.getInputStream();
				BufferedReader rd2 = new BufferedReader(new InputStreamReader(is2));
				String line2;
				while ((line2 = rd2.readLine()) != null) {
						logger.debug("BufferedReader2=" + line2 );
				}
				rd2.close();
			}
			// - eof insert to check for 401 body
*/

			connection.setRequestMethod("POST");						// GET POST HEAD OPTIONS PUT DELETE TRACE
			connection.setRequestProperty("Connection", "Keep-Alive");	// https://docs.oracle.com/javase/8/docs/api/java/net/URLConnection.html#setRequestProperty-java.lang.String-java.lang.String-
			connection.setRequestProperty("Content-Type",
					"application/x-www-form-urlencoded");
			connection.setRequestProperty("Content-Length",
					Integer.toString(urlParameters.getBytes().length));

            logger.debug("urlParameters=" + urlParameters );		// 15okt24 Ptro debug why we cannot connect edimax
			String userpass = username + ":" + password;
			// String userpass = username + ":edimax001";			// 15okt24 ptro force password, now fixed as we solved "== null" by equals()

			/*
					String credentials = "ptt" + ":" + "ptt123";
					String encoding = Base64Converter.encode(credentials.getBytes("UTF-8"));
					URLConnection uc = url.openConnection();
					uc.setRequestProperty("Authorization", String.format("Basic %s", encoding));
			*/
			// Digest authentication is far more complex than just sending username:password
			// String basicAuth = "Basic "
			String basicAuth = "Basic "
					+ DatatypeConverter.printBase64Binary(userpass.getBytes());
            basicAuth = "Basic " + userpass;								// testing
            logger.debug("basicAuth=" + userpass + ", cod64=" + basicAuth );		// 15okt24 Ptro debug why we cannot connect edimax
			connection.setRequestProperty("Authorization", basicAuth);

			connection.setUseCaches(false);		// always try to get a fresh copy 
			connection.setDoOutput(true);		// use the URL connection for output,

            logger.debug("HttpURLConnection=" + connection );		// 15okt24 Ptro debug why we cannot connect edimax
			//  HttpURLConnection=sun.net.www.protocol.http.HttpURLConnection:http://192.168.1.130:10000/smartplug.cgi 

			// Send request 
			DataOutputStream wr = new DataOutputStream(			// class write primitive Java data types to an output stream in a portable way.
					connection.getOutputStream());				
            logger.debug("wr.write(urlParameters.getBytes())=" + urlParameters  );		// 15okt24 Ptro debug why we cannot connect edimax																// method close() is automatically called when exiting a try-with-resource block.
			wr.write(urlParameters.getBytes());					// write number byte to the OutputStream.
			wr.close();
			// 2024-10-15 21:41:36.035 [DEBUG] [inding.edimax.internal.EdimaxBinding] HTTPSend- wr.write(urlParameters.getBytes()); done & closed                                                                
            // followed by our finnally and  followed by ioException as catched in EdimaxBinding.java
            logger.debug("wr.write(urlParameters.getBytes()); done & closed" );		// 15okt24 Ptro debug why we cannot connect edimax

            logger.debug("before  InputStream is = connection.getInputStream()" );		// 15okt24 Ptro debug why we cannot connect edimax
			// note: on curl we get  back 401: < WWW-Authenticate: Digest realm="SP1101W", nonce="1845ce45bd3a5dac6fe01105c63bc416", qop="auth"

			// check response
			// 2024-10-15 22:06:17.831 [DEBUG] [inding.edimax.internal.EdimaxBinding] - responseCode =401
			//    see for all posibel codes: [https://docs.oracle.com/javase/8/docs/api/java/net/HttpURLConnection.html]
            logger.debug("responseCode    =" + connection.getResponseCode() );		// 15okt24 Ptro debug why we cannot connect edimax
            logger.debug("responseMessage =" + connection.getResponseMessage() );		// 15okt24 Ptro debug why we cannot connect edimax
			// not we have a faulty/error , we must retrieve the tream by , read [https://stackoverflow.com/questions/25011927/how-to-get-response-body-using-httpurlconnection-when-code-other-than-2xx-is-re]


             if (connection.getResponseCode() == 401) {
				// for getHeaderFields()
				//		read [https://www.codejava.net/java-se/networking/how-to-use-java-urlconnection-and-httpurlconnection]
                logger.debug("getHeaderFields()=" + connection.getHeaderFields());
				//	2024-10-16 01:21:16.210 [DEBUG] [inding.edimax.internal.EdimaxBinding] - 
				//		getHeaderFields()={null=[HTTP/1.1 401 Unauthorized], 
				//		Server=[lighttpd/1.4.31-devel-325M], 
				//		WWW-Authenticate=[Digest realm="SP1101W", nonce="4eefd0c45d40d370f4fe0b3e9d225057", qop="auth"], 
				//		Content-Length=[333], 
				//		Date=[Wed, 16 Oct 2024 00:21:25 GMT], 
				//		Content-Type=[text/html]} 

				// sof===================================================================================================================                
                //
				//                   routine to culculate and do digest authentication
                //
				logger.debug("(check if it works) calculateNonce()" + calculateNonce() );
				logger.debug("(check with hex) calculateNonce()="   + getHex(calculateNonce().getBytes()) );  
				//	2024-10-16 02:06:17.163 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
				// 		check if it works) calculateNonce()= ***rubbisch**
				//	2024-10-16 02:06:17.163 [DEBUG] [inding.edimax.internal.EdimaxBinding] -
				//		check with hex) calculateNonce()=D38AEFBFBD79EFBFBDEFBFBDEFBFBD6BEFBFBD0D037DEFBFBDEFBFBD606D 

				// convert string to byte array
				// 	byte[] b = string.getBytes();
				// 	byte[] b = string.getBytes(Charset.forName("UTF-8"));
				// 	byte[] b = string.getBytes(StandardCharsets.UTF_8); // Java 7+ only

                logger.debug("getHeaderFields(WWW-Authenticate)=" + connection.getHeaderField("WWW-Authenticate"));

/*
				// getHeaderFields(WWW-Authenticate)=Digest realm="SP1101W", nonce="e8fe8401d62aae86f8a6de1202fcbf4c", qop="auth"

				HashMap<String, String> headerValues = parseHeader(connection.getHeaderField("WWW-Authenticate"));
                String method = request.getMethod();  // ??

                    String ha1 = DigestUtils.md5Hex(userName + ":" + realm + ":" + password);
                    String qop = headerValues.get("qop");		// "quality of protection" (qop)
                    String ha2;
                    String reqURI = headerValues.get("uri");
				//
                //  if (!StringUtils.isBlank(qop) && qop.equals("auth-int")) {
                //      String entityBodyMd5 = DigestUtils.md5Hex(requestBody);
                //      ha2 = DigestUtils.md5Hex(method + ":" + reqURI + ":" + entityBodyMd5);
                //  } else {
				//
                //      ha2 = DigestUtils.md5Hex(method + ":" + reqURI);
                //  }
						ha2 = DigestUtils.md5Hex(method + ":" + reqURI);
                    String serverResponse

*/
				// eof ===================================================================================================================

				// 2024-10-16 00:51:58.998 [DEBUG] [inding.edimax.internal.EdimaxBinding] - 
				// 		getHeaderFields()={null=[HTTP/1.1 401 Unauthorized], 
				//		Server=[lighttpd/1.4.31-devel-325M], 
				//		WWW-Authenticate=[Digest realm="SP1101W", nonce="a3ab1746c7dd6c9c41d905b1f635abec", qop="auth"], 
				//		Content-Length=[333], 
				//		Date=[Tue, 15 Oct 2024 23:52:09 GMT], 
				//		Content-Type=[text/html]} 

				BufferedReader br = null;
			    br = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
			    String strCurrentLine;
		        while ((strCurrentLine = br.readLine()) != null) {
						logger.debug("errorstream =" + strCurrentLine );
				/*
				2024-10-15 22:28:59.862 [DEBUG] [inding.edimax.internal.EdimaxBinding] - responseMessage =Unauthorized 
				2024-10-15 22:28:59.863 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream =<?xml version="1.0" encoding="iso-8859-1"?> 
				2024-10-15 22:28:59.864 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream =<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" 
				2024-10-15 22:28:59.864 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream =         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"> 
				2024-10-15 22:28:59.866 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream =<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en"> 
				2024-10-15 22:28:59.867 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream = <head> 
				2024-10-15 22:28:59.868 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream =  <title>401 - Unauthorized</title> 
				2024-10-15 22:28:59.869 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream = </head> 
				2024-10-15 22:28:59.870 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream = <body> 
				2024-10-15 22:28:59.871 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream =  <h1></h1> 
				2024-10-15 22:28:59.872 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream = </body> 
				2024-10-15 22:28:59.872 [DEBUG] [inding.edimax.internal.EdimaxBinding] - errorstream =</html> 
				*/

		        }
			}

			// Get Response
			InputStream is = connection.getInputStream();		// this produces an IOException
																// IOException- if an Input/Output error occurs while creating the 
																//   input stream or if this socket is closed or the given socket 
																//   is not connected, or the socket input has been shut down 
																//   using shutdownInput()
            logger.debug("after InputStream is = connection.getInputStream()" );		// 15okt24 Ptro debug why we cannot connect edimax

			BufferedReader rd = new BufferedReader(new InputStreamReader(is));
			StringBuilder response = new StringBuilder();
			String line;
			while ((line = rd.readLine()) != null) {
				response.append(line);
				response.append('\r');
			}
			rd.close();
            logger.debug("edimax returned=" + response.toString()  );		// 15okt24 Ptro debug why we cannot connect edimax
			return response.toString();
		} finally {								// The finally block is always run after the try block ends
			if (connection != null) {
				// 2024-10-15 21:41:36.064 [DEBUG] [inding.edimax.internal.EdimaxBinding] HTTPSend- executePost: try finally connection.disconnect()                                                                 
				// followed by ioException as catched in EdimaxBinding.java
                logger.debug("executePost: try finally connection.disconnect() " );		// 15okt24 Ptro debug why we cannot connect edimax
				connection.disconnect();
			}
		}
	}

}
