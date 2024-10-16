/*
 // doc: https://usamadar.com/2012/06/11/implementing-http-digest-authentication-in-java/
 // from https://gist.github.com/usamadar/2912088
 * To change this template, choose Tools | Templates
 * and open the template in the editor.

1) Client would request a resource i.e.

	GET /HTTPDigestServer/HttpDigestAuth?username=usm

2) Server would send back an HTTP 401 indicating it’s a protected resource and needs authorization. 

	In addition to sending back a 401 the Server will include an HTTP header called WWW-Authenticate, 
	in this header there will be a field called “nonce” which basically is a challenge from the server. 
	
	In addition to nonce , server optionally include a field called  qop, which basically determines 
	which algorithm will be used by client to calculate the response.

	The possible values of qop are auth and auth-int. 
	Server can also decide to not include this field, 
	in which case the response will be calculated by the client in the old RFC 2069 style.

3) Client will then calculate a few hashes, 
	combine them to create another hash called “response” 
	this will be sent in a HTTP header called Authorization along with some other fields for example

	GET /HTTPDigestServer/HttpDigestAuth?username=usm HTTP/1.1
		Host: 127.0.0.1:8888
		Connection: keep-alive
		Authorization: Digest username="usm", realm="abc.com", nonce="464586d93e858f45e59b4cb8e83ce89f", 
		uri="/HTTPDigestServer/HttpDigestAuth?username=usm",
		response="598efaca64f9e7f02d92a13c50e74ad0", opaque="9dfa6fe2f0325895ece2bbab4a4837bd", 
		qop=auth, nc=00000003, cnonce="c4020839a1c2ccb6"
		User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.54 Safari/536.5
		Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*//*;q=0.8

		Accept-Encoding: gzip,deflate,sdch
		Accept-Language: en-US,en;q=0.8
		Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3
		Cookie: JSESSIONID=272EAF671C64242C240D2D08F690839C

The server then verifies if the response value is correct or not. 
	You can read the details of how the calculations are done on the 
	nice wikipedia article here [https://en.wikipedia.org/wiki/Digest_access_authentication]


 */
package com.example.http.authenticate;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * TODO stale support 
 * TODO give this servlet and package a correct name 
 * @author Usama Dar( munir.usama@gmail.com)
 */
public class HttpDigestAuthServlet extends HttpServlet {

    private String authMethod = "auth";
    private String userName = "usm";
    private String password = "password";
    private String realm = "example.com";

    public String nonce;
    public ScheduledExecutorService nonceRefreshExecutor;

    /**
     * Default constructor to initialize stuff
     *
     */
    public HttpDigestAuthServlet() throws IOException, Exception {

        nonce = calculateNonce();
        
        nonceRefreshExecutor = Executors.newScheduledThreadPool(1);

        nonceRefreshExecutor.scheduleAtFixedRate(new Runnable() {

            public void run() {
                log("Refreshing Nonce....");
                nonce = calculateNonce();
            }
        }, 1, 1, TimeUnit.MINUTES);

    }

    protected void authenticate(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();

        String requestBody = readRequestBody(request);

        try {
			//  [https://docs.oracle.com/javaee/7/api/javax/servlet/http/HttpServletRequest.html]
			// and fyi about getting header/state servlet informatie [https://www.baeldung.com/java-http-request-client-info]
			// Returns the value of the specified request header as a String.
			// for edimax we get: WWW-Authenticate: Digest realm="SP1101W", nonce="1845ce45bd3a5dac6fe01105c63bc416", qop="auth"
            String authHeader = request.getHeader("Authorization");
            if (StringUtils.isBlank(authHeader)) {
                response.addHeader("WWW-Authenticate", getAuthenticateHeader());	// processing realm, nonce & qop
				// https://javaee.github.io/javaee-spec/javadocs/javax/servlet/http/HttpServletResponse.html
				//		Sends an error response to the client using the specified status and clears the buffer.
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            } else {
				//  WWW-Authenticate: Digest realm="SP1101W", nonce="1845ce45bd3a5dac6fe01105c63bc416", qop="auth"

                if (authHeader.startsWith("Digest")) {
                    // parse the values of the Authentication header into a hashmap
                    HashMap<String, String> headerValues = parseHeader(authHeader);

                    String method = request.getMethod();

                    String ha1 = DigestUtils.md5Hex(userName + ":" + realm + ":" + password);

                    String qop = headerValues.get("qop");

                    String ha2;

                    String reqURI = headerValues.get("uri");

                    if (!StringUtils.isBlank(qop) && qop.equals("auth-int")) {
                        String entityBodyMd5 = DigestUtils.md5Hex(requestBody);
                        ha2 = DigestUtils.md5Hex(method + ":" + reqURI + ":" + entityBodyMd5);
                    } else {
                        ha2 = DigestUtils.md5Hex(method + ":" + reqURI);
                    }

                    String serverResponse;

                    if (StringUtils.isBlank(qop)) {
                        serverResponse = DigestUtils.md5Hex(ha1 + ":" + nonce + ":" + ha2);

                    } else {
                        String domain = headerValues.get("realm");

                        String nonceCount = headerValues.get("nc");
                        String clientNonce = headerValues.get("cnonce");

                        serverResponse = DigestUtils.md5Hex(ha1 + ":" + nonce + ":"
                                + nonceCount + ":" + clientNonce + ":" + qop + ":" + ha2);

                    }
                    String clientResponse = headerValues.get("response");

                    if (!serverResponse.equals(clientResponse)) {
                        response.addHeader("WWW-Authenticate", getAuthenticateHeader());
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    }

                } else {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, " This Servlet only supports Digest Authorization");
                }

            }

            /*
             * out.println("<head>"); out.println("<title>Servlet
             * HttpDigestAuth</title>"); out.println("</head>");
             * out.println("<body>"); out.println("<h1>Servlet HttpDigestAuth at
             * " + request.getContextPath () + "</h1>"); out.println("</body>");
             * out.println("</html>");
             */
        } finally {
            out.close();
        }
    }

    /**
     * Handles the HTTP
     * <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        authenticate(request, response);
    }

    /**
     * Handles the HTTP
     * <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        authenticate(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "This Servlet Implements The HTTP Digest Auth as per RFC2617";
    }// </editor-fold>

    /**
     * Gets the Authorization header string minus the "AuthType" and returns a
     * hashMap of keys and values
     *
     * @param headerString
     * @return
     */
    private HashMap<String, String> parseHeader(String headerString) {
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

    private String getAuthenticateHeader() {
        String header = "";

        header += "Digest realm=\"" + realm + "\",";
        if (!StringUtils.isBlank(authMethod)) {
            header += "qop=" + authMethod + ",";
        }
        header += "nonce=\"" + nonce + "\",";
        header += "opaque=\"" + getOpaque(realm, nonce) + "\"";

        return header;
    }

    /**
     * Calculate the nonce based on current time-stamp upto the second, and a
     * random seed
     *
     * @return
     */
    public String calculateNonce() {
        Date d = new Date();
        SimpleDateFormat f = new SimpleDateFormat("yyyy:MM:dd:hh:mm:ss");
        String fmtDate = f.format(d);
        Random rand = new Random(100000);
        Integer randomInt = rand.nextInt();
        return DigestUtils.md5Hex(fmtDate + randomInt.toString());
    }

    private String getOpaque(String domain, String nonce) {
        return DigestUtils.md5Hex(domain + nonce);
    }

    /**
     * Returns the request body as String
     *
     * @param request
     * @return
     * @throws IOException
     */
    private String readRequestBody(HttpServletRequest request) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = null;
        try {
            InputStream inputStream = request.getInputStream();
            if (inputStream != null) {
                bufferedReader = new BufferedReader(new InputStreamReader(
                        inputStream));
                char[] charBuffer = new char[128];
                int bytesRead = -1;
                while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
                    stringBuilder.append(charBuffer, 0, bytesRead);
                }
            } else {
                stringBuilder.append("");
            }
        } catch (IOException ex) {
            throw ex;
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException ex) {
                    throw ex;
                }
            }
        }
        String body = stringBuilder.toString();
        return body;
    }
  
}

