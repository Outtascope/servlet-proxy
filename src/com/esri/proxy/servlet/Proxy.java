package com.esri.proxy.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author Christopher C. Perry &lt;perrych2@msu.edu&gt;
 * https://github.com/Esri/resource-proxy
 */
public class Proxy extends HttpServlet {
  private String PROXY_REFERER = "http://localhost/proxy.jsp";
  private static final String DEFAULT_OAUTH = "https://www.arcgis.com/sharing/oauth2/";
  private static final int CLEAN_RATEMAP_AFTER = 10000;

  /**
   * Processes requests for both HTTP <code>GET</code> and <code>POST</code> methods.
   *
   * @param request servlet request
   * @param response servlet response
   * @throws ServletException if a servlet-specific error occurs
   * @throws IOException if an I/O error occurs
   */
  protected void processRequest(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException
  {
    response.setContentType("text/html;charset=UTF-8");
    try (PrintWriter out = response.getWriter()) {
      String uri = request.getQueryString();
      _log(Level.INFO, "Creating request for: " + uri);
      ServerUrl serverUrl;
      boolean passThrough = false;
      try {
        try {
        out.clear();
        out = pageContext.pushBody();

        if (uri == null || uri.isEmpty()){
          String errorMessage = "This proxy does not support empty parameters.";
          _log(Level.WARNING, errorMessage);
          sendErrorResponse(response, errorMessage, "400 - " + errorMessage, HttpServletResponse.SC_BAD_REQUEST);
          return;
        }

        if (uri.equalsIgnoreCase("ping")){
          String checkConfig = (getConfig().canReadProxyConfig() == true) ? "OK": "Not Readable";
          String checkLog = (okToLog() == true) ? "OK": "Not Exist/Readable";
          _sendPingMessage(response, version, checkConfig, checkLog);
          return;
        }

        //check if the uri is encoded then decode it
        if (uri.toLowerCase().startsWith("http%3a%2f%2f") || uri.toLowerCase().startsWith("https%3a%2f%2f")) uri= URLDecoder.decode(uri, "UTF-8");

        String[] allowedReferers = getConfig().getAllowedReferers();
        if (allowedReferers != null && allowedReferers.length > 0 && request.getHeader("referer") != null){
          setReferer(request.getHeader("referer")); //replace PROXY_REFERER with real proxy
          String hostReferer = request.getHeader("referer");
          try{
            //only use the hostname of the referer url
            hostReferer = new URL(request.getHeader("referer")).getHost();
          }catch(Exception e){
            _log(Level.WARNING, "Proxy is being used from an invalid referer: " + request.getHeader("referer"));
            sendErrorResponse(response, "Error verifying referer. ", "403 - Forbidden: Access is denied.", HttpServletResponse.SC_FORBIDDEN);
            return;
          }
          if (!checkReferer(allowedReferers, hostReferer)){
            _log(Level.WARNING, "Proxy is being used from an unknown referer: " + request.getHeader("referer"));
            sendErrorResponse(response, "Unsupported referer. ", "403 - Forbidden: Access is denied.", HttpServletResponse.SC_FORBIDDEN);
            return;
          }
        }

        //Check to see if allowed referer list is specified and reject if referer is null
        if (request.getHeader("referer") == null && allowedReferers != null && !allowedReferers[0].equals("*"))
        {
          _log(Level.WARNING, "Proxy is being called by a null referer.  Access denied.");
          sendErrorResponse(response, "Current proxy configuration settings do not allow requests which do not include a referer header.", "403 - Forbidden: Access is denied.", HttpServletResponse.SC_FORBIDDEN);
          return;
        }

        serverUrl = getConfig().getConfigServerUrl(uri);
        if (serverUrl == null) {
          //if no serverUrl found, send error message and get out.
          _sendURLMismatchError(response, uri);
          return;
        }
        passThrough = serverUrl == null;
      } catch (IllegalStateException e) {
        _log(Level.WARNING, "Proxy is being used for an unsupported service: " + uri);
        _sendURLMismatchError(response, uri);
        return;
      }

      //Throttling: checking the rate limit coming from particular referrer
      if (!passThrough && serverUrl.getRateLimit() > -1) {
        synchronized(_rateMapLock){
          ConcurrentHashMap<String, RateMeter> ratemap = (ConcurrentHashMap<String, RateMeter>)application.getAttribute("rateMap");
          if (ratemap == null){
            ratemap = new ConcurrentHashMap<String, RateMeter>();
            application.setAttribute("rateMap", ratemap);
            application.setAttribute("rateMap_cleanup_counter", 0);
          }

          String key = "[" + serverUrl.getUrl() + "]x[" + request.getRemoteAddr() + "]";
          RateMeter rate = ratemap.get(key);
          if (rate == null) {
            rate = new RateMeter(serverUrl.getRateLimit(), serverUrl.getRateLimitPeriod());
            RateMeter rateCheck = ratemap.putIfAbsent(key, rate);
            if (rateCheck != null){
              rate = rateCheck;
            }
          }
          if (!rate.click()) {
            _log(Level.WARNING, 
                "Pair " + key + " is throttled to " + serverUrl.getRateLimit() + " requests per " 
              + serverUrl.getRateLimitPeriod() + " minute(s). Come back later.");

            sendErrorResponse(response, 
                "This is a metered resource, number of requests have exceeded the rate limit interval.",
                    "Error 429 - Too Many Requests", 429);
            return;
          }

          //making sure the rateMap gets periodically cleaned up so it does not grow uncontrollably
          int cnt = ((Integer)application.getAttribute("rateMap_cleanup_counter")).intValue();
          cnt++;
          if (cnt >= CLEAN_RATEMAP_AFTER) {
            cnt = 0;
            cleanUpRatemap(ratemap);
          }
          application.setAttribute("rateMap_cleanup_counter", new Integer(cnt));
        };
      }

      //readying body (if any) of POST request
      byte[] postBody = readRequestPostBody(request);
      String post = new String(postBody);

      //if token comes with client request, it takes precedence over token or credentials stored in configuration
      boolean hasClientToken = uri.contains("?token=") || uri.contains("&token=") || post.contains("?token=") || post.contains("&token=");
      String token = "";
      if (!passThrough && !hasClientToken) {
        // Get new token and append to the request.
        // But first, look up in the application scope, maybe it's already there:
        token = (String)application.getAttribute("token_for_" + serverUrl.getUrl());
        boolean tokenIsInApplicationScope = token != null && !token.isEmpty();

        //if still no token, let's see if there are credentials stored in configuration which we can use to obtain new token
        if (!tokenIsInApplicationScope){
          token = getNewTokenIfCredentialsAreSpecified(serverUrl, uri);
        }

        if (token != null && !token.isEmpty() && !tokenIsInApplicationScope) {
          //storing the token in Application scope, to do not waste time on requesting new one until it expires or the app is restarted.
          application.setAttribute("token_for_" + serverUrl.getUrl(), token);
        }
      }

      //forwarding original request
      HttpURLConnection con = null;
      con = forwardToServer(request, addTokenToUri(uri, token), postBody);
      //passing header info from request to connection
      passHeadersInfo(request, con);

      if (passThrough || token == null || token.isEmpty() || hasClientToken) {
        //if token is not required or provided by the client, just fetch the response as is:
        fetchAndPassBackToClient(con, response, true);
      } else {
        //credentials for secured service have come from configuration file:
        //it means that the proxy is responsible for making sure they were properly applied:

        //first attempt to send the request:
        boolean tokenRequired = fetchAndPassBackToClient(con, response, false);

        //checking if previously used token has expired and needs to be renewed
        if (tokenRequired) {
          _log(Level.INFO, "Renewing token and trying again.");
          //server returned error - potential cause: token has expired.
          //we'll do second attempt to call the server with renewed token:
          token = getNewTokenIfCredentialsAreSpecified(serverUrl, uri);
          con = forwardToServer(request, addTokenToUri(uri, token), postBody);
          passHeadersInfo(request, con); //passing header info from request to connection

          //storing the token in Application scope, to do not waste time on requesting new one until it expires or the app is restarted.
          synchronized(this){
            application.setAttribute("token_for_" + serverUrl.getUrl(), token);
          }

          fetchAndPassBackToClient(con, response, true);
        }
      }
    } catch (FileNotFoundException e) {
      try {
        _log("404 Not Found .", e);
        response.sendError(404, e.getLocalizedMessage() + " is NOT Found.");
        return;
      } catch (IOException finalErr) {
        _log("There was an error sending a response to the client.  Will not try again.", finalErr);
      }
    } catch (IOException e) {
      try {
        _log("A fatal proxy error occurred.", e);
        response.sendError(500, e.getLocalizedMessage());
        return;
      } catch (IOException finalErr) {
        _log("There was an error sending a response to the client.  Will not try again.", finalErr);
      }
    }    
  }

  // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
  /**
   * Handles the HTTP <code>GET</code> method.
   *
   * @param request servlet request
   * @param response servlet response
   * @throws ServletException if a servlet-specific error occurs
   * @throws IOException if an I/O error occurs
   */
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    processRequest(request, response);
  }

  /**
   * Handles the HTTP <code>POST</code> method.
   *
   * @param request servlet request
   * @param response servlet response
   * @throws ServletException if a servlet-specific error occurs
   * @throws IOException if an I/O error occurs
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    processRequest(request, response);
  }

  /**
   * Returns a short description of the servlet.
   *
   * @return a String containing servlet description
   */
  @Override
  public String getServletInfo() {
    return "Short description";
  }// </editor-fold>

  
  
  
  //setReferer if real referer exist
  private void setReferer(String r){
    PROXY_REFERER = r;
  }

  private byte[] readRequestPostBody(HttpServletRequest request) throws IOException{
    int clength = request.getContentLength();
    if(clength > 0) {
      byte[] bytes = new byte[clength];
      DataInputStream dataIs = new DataInputStream(request.getInputStream());

      dataIs.readFully(bytes);
      dataIs.close();
      return bytes;
    }

    return new byte[0];
  }

  private HttpURLConnection forwardToServer(HttpServletRequest request, String uri, byte[] postBody) throws IOException{
    return postBody.length > 0 ?
        doHTTPRequest(uri, postBody, "POST", request.getHeader("Referer"), request.getContentType()) :
        doHTTPRequest(uri, request.getMethod());
  }

  private boolean fetchAndPassBackToClient(HttpURLConnection con, HttpServletResponse clientResponse, boolean ignoreAuthenticationErrors) throws IOException{
    if (con!=null){
      Map<String, List<String>> headerFields = con.getHeaderFields();

      Set<String> headerFieldsSet = headerFields.keySet();
      Iterator<String> hearerFieldsIter = headerFieldsSet.iterator();

      while (hearerFieldsIter.hasNext()){
        String headerFieldKey = hearerFieldsIter.next();
        List<String> headerFieldValue = headerFields.get(headerFieldKey);
        StringBuilder sb = new StringBuilder();
        for (String value : headerFieldValue) {
          sb.append(value);
          sb.append("");
        }
        if (headerFieldKey != null) clientResponse.addHeader(headerFieldKey, sb.toString());
      }

      InputStream byteStream;
      if (con.getResponseCode() >= 400 && con.getErrorStream() != null){
        if (ignoreAuthenticationErrors && (con.getResponseCode() == 498 || con.getResponseCode() == 499)) return true;
        byteStream = con.getErrorStream();
      }else{
        byteStream = con.getInputStream();
      }

      clientResponse.setStatus(con.getResponseCode());

      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      final int length = 5000;

      byte[] bytes = new byte[length];
      int bytesRead = 0;

      while ((bytesRead = byteStream.read(bytes, 0, length)) > 0) {
        buffer.write(bytes, 0, bytesRead);
      }
      buffer.flush();

      byte[] byteResponse = buffer.toByteArray();
      OutputStream ostream = clientResponse.getOutputStream();
      ostream.write(byteResponse);
      ostream.close();
      byteStream.close();
    }
    return false;
  }

  private boolean passHeadersInfo(HttpServletRequest request, HttpURLConnection con) {
    Enumeration headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String key = (String) headerNames.nextElement();
      String value = request.getHeader(key);
      if (!key.equalsIgnoreCase("host")) con.setRequestProperty(key, value);
    }
    return true;
  }

  private HttpURLConnection doHTTPRequest(String uri, String method) throws IOException{
    byte[] bytes = null;
    String contentType = null;
    if (method.equals("POST")){
      String[] uriArray = uri.split("\\?");

      if (uriArray.length > 1){
        contentType = "application/x-www-form-urlencoded";
        String queryString = uriArray[1];

        bytes = URLEncoder.encode(queryString, "UTF-8").getBytes();
      }
    }
    return doHTTPRequest(uri, bytes, method, PROXY_REFERER, contentType);
  }

  private HttpURLConnection doHTTPRequest(String uri, byte[] bytes, String method, String referer, String contentType) throws IOException{
    URL url = new URL(uri);
    HttpURLConnection con = (HttpURLConnection)url.openConnection();

    con.setConnectTimeout(5000);
    con.setReadTimeout(10000);

    con.setRequestProperty("Referer", referer);
    con.setRequestMethod(method);

    if (bytes != null && bytes.length > 0 || method.equals("POST"))
    {
      if (bytes == null){
        bytes = new byte[0];
      }

      con.setRequestMethod("POST");
      con.setDoOutput(true);
      if (contentType == null || contentType.isEmpty())
      {
        contentType = "application/x-www-form-urlencoded";
      }

      con.setRequestProperty("Content-Type", contentType);

      OutputStream os = con.getOutputStream();
      os.write(bytes);
    }
    return con;
  }

  private String webResponseToString(HttpURLConnection con) throws IOException{
    InputStream in = con.getInputStream();

    Reader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
    StringBuffer content = new StringBuffer();
    char[] buffer = new char[5000];
    int n;

    while ( ( n = reader.read(buffer)) != -1 ) {
      content.append(buffer, 0, n);
    }
    reader.close();

    String strResponse = content.toString();

    return strResponse;
  }

  private String getNewTokenIfCredentialsAreSpecified(ServerUrl su, String url) throws IOException{
    String token = "";
    boolean isUserLogin = (su.getUsername() != null && !su.getUsername().isEmpty()) && (su.getPassword() != null && !su.getPassword().isEmpty());
    boolean isAppLogin = (su.getClientId() != null && !su.getClientId().isEmpty()) && (su.getClientSecret() != null && !su.getClientSecret().isEmpty());
    if (isUserLogin || isAppLogin) {
      _log(Level.INFO, "Matching credentials found in configuration file. OAuth 2.0 mode: " + isAppLogin);
      if (isAppLogin) {
        //OAuth 2.0 mode authentication
        //"App Login" - authenticating using client_id and client_secret stored in config
        if (su.getOAuth2Endpoint() == null || su.getOAuth2Endpoint().isEmpty()){
          su.setOAuth2Endpoint(DEFAULT_OAUTH);
        }
        if (su.getOAuth2Endpoint().charAt(su.getOAuth2Endpoint().length() - 1) != '/') {
          su.setOAuth2Endpoint(su.getOAuth2Endpoint() + "/");
        }
        _log(Level.INFO, "Service is secured by " + su.getOAuth2Endpoint() + ": getting new token...");
        String uri = su.getOAuth2Endpoint() + "token?client_id=" + su.getClientId() + "&client_secret=" + su.getClientSecret() + "&grant_type=client_credentials&f=json";
        String tokenResponse = webResponseToString(doHTTPRequest(uri, "POST"));
        token = extractToken(tokenResponse, "access_token");
        if (token != null && !token.isEmpty()) {
          token = exchangePortalTokenForServerToken(token, su);
        }
      } else {
        //standalone ArcGIS Server token-based authentication

        //if a request is already being made to generate a token, just let it go
        if (url.toLowerCase().contains("/generatetoken")){
          String tokenResponse = webResponseToString(doHTTPRequest(url, "POST"));
          token = extractToken(tokenResponse, "token");
          return token;
        }

        String infoUrl = "";
        //lets look for '/rest/' in the request url (could be 'rest/services', 'rest/community'...)
        if (url.toLowerCase().contains("/rest/"))
        {
          infoUrl = url.substring(0, url.indexOf("/rest/"));
          infoUrl += "/rest/info?f=json";
          //if we don't find 'rest', lets look for the portal specific 'sharing' instead
        } else if (url.toLowerCase().contains("/sharing/"))
        {
          infoUrl = url.substring(0, url.indexOf("sharing"));
          infoUrl += "/sharing/rest/info?f=json";
        } else
        {
          return "-1"; //return -1, signaling that infourl can not be found
        }

        if (infoUrl != "")
        {
          _log(Level.INFO, "[Info]: Querying security endpoint...");

          String tokenServiceUri = su.getTokenServiceUri();

          if (tokenServiceUri == null || tokenServiceUri.isEmpty())
          {
            _log(Level.INFO, "Token URL not cached.  Querying rest info page...");
            String infoResponse = webResponseToString(doHTTPRequest(infoUrl, "GET"));
            tokenServiceUri = getJsonValue(infoResponse, "tokenServicesUrl");
            su.setTokenServiceUri(tokenServiceUri);
          }

          if (tokenServiceUri != null & !tokenServiceUri.isEmpty())
          {
            _log(Level.INFO, "[Info]: Service is secured by " + tokenServiceUri + ": getting new token...");
            String uri = tokenServiceUri + "?f=json&request=getToken&referer=" + PROXY_REFERER + "&expiration=60&username=" + su.getUsername() + "&password=" + su.getPassword();
            String tokenResponse = webResponseToString(doHTTPRequest(uri, "POST"));
            token = extractToken(tokenResponse, "token");
          }
        }
      }
    }
    return token;
  }

  private boolean checkReferer(String[] allowedReferers, String referer){
    if (allowedReferers != null && allowedReferers.length > 0){
      if (allowedReferers.length == 1 && allowedReferers[0].equals("*")) return true; //speed-up
      for (String allowedReferer : allowedReferers)
      {
        allowedReferer = allowedReferer.replaceAll("\\s", "");
        if (referer.toLowerCase().equals(allowedReferer.toLowerCase()))
        {
          return true;
        } else if (allowedReferer.contains("*")) { //try if the allowed referer contains wildcard for subdomain
          if (checkWildcardSubdomain(allowedReferer, referer)) {
            return true; //return true if match wildcard subdomain
          }
        }
      }
      return false;//no-match
    }
    return true;//when allowedReferer is null, then allow everything
  }


  private boolean checkWildcardSubdomain(String allowedReferer, String referer)
  {
    String[] allowedRefererParts = allowedReferer.split("(\\.)");
    String[] refererParts = referer.split("(\\.)");

    int allowedIndex = allowedRefererParts.length-1;
    int refererIndex = refererParts.length-1;
    while(allowedIndex >= 0 && refererIndex >= 0){
      if (allowedRefererParts[allowedIndex].equalsIgnoreCase(refererParts[refererIndex]))
      {
        allowedIndex = allowedIndex - 1;
        refererIndex = refererIndex - 1;
      } else {
        if(allowedRefererParts[allowedIndex].equals("*"))
        {
          allowedIndex = allowedIndex - 1;
          refererIndex = refererIndex - 1;
          continue; //next
        }
        return false;
      }
    }
    return true;
}

  private String getFullUrl(String url)
  {
    return url.startsWith("//") ? url.replace("//","https://") : url;
  }

  private String exchangePortalTokenForServerToken(String portalToken, ServerUrl su) throws IOException
  {
    String url = getFullUrl(su.getUrl());
    _log(Level.INFO, "[Info]: Exchanging Portal token for Server-specific token for " + url + "...");
    String uri = su.getOAuth2Endpoint().substring(0, su.getOAuth2Endpoint().toLowerCase().indexOf("/oauth2/")) +
         "/generateToken?token=" + portalToken + "&serverURL=" + url + "&f=json";
    String tokenResponse = webResponseToString(doHTTPRequest(uri, "GET"));
    return extractToken(tokenResponse, "token");
  }

  private String addTokenToUri(String uri, String token)
  {
    if (token != null && !token.isEmpty())
    {
      uri += uri.contains("?") ? "&token=" + token : "?token=" + token;
    }
    return uri;
  }

  private String extractToken(String tokenResponse, String key)
  {
    String token = getJsonValue(tokenResponse, key);
    if (token == null || token.isEmpty())
    {
      _log(Level.WARNING, "Token cannot be obtained: " + tokenResponse);
    } else {
      _log(Level.INFO, "Token obtained: " + token);
    }
    return token;
  }

  private String getJsonValue(String text, String key)
  {
    _log(Level.FINE, "JSON Response: " + text);
    int i = text.indexOf(key);
    String value = "";
    if (i > -1)
    {
      value = text.substring(text.indexOf(':', i) + 1).trim();
      value = (value.length() > 0 && value.charAt(0) == '"') ?
          value.substring(1, value.indexOf('"', 1)) :
          value.substring(0, Math.max(0, Math.min(Math.min(value.indexOf(","), value.indexOf("]")), value.indexOf("}"))));
    }
    _log(Level.FINE, "Extracted Value: " + value);
    return value;
  }

  private void cleanUpRatemap(ConcurrentHashMap<String, RateMeter> ratemap)
  {
    Set<Map.Entry<String, RateMeter>> entrySet = ratemap.entrySet();
    for (Map.Entry<String,RateMeter> entry : entrySet)
    {
      RateMeter rate = entry.getValue();
      if (rate.canBeCleaned())
      {
        ratemap.remove(entry.getKey(), rate);
      }
    }
  }

/**
* Static
*/

  private static ProxyConfig getConfig()  throws IOException
  {
    ProxyConfig config = ProxyConfig.getCurrentConfig();
    if (config != null)
    {
      return config;
    } else {
      throw new FileNotFoundException("The proxy configuration file");
    }
  }

  //writing Log file
  private static Object _lockobject = new Object();
  private static Logger logger = Logger.getLogger("ESRI_PROXY_LOGGER");

  private boolean okToLog(){
    try
    {
      ProxyConfig proxyConfig = getConfig();
      String filename = proxyConfig.getLogFile();
      return filename != null && filename != "" && !filename.isEmpty() && logger != null;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  private static void _log(Level level, String s, Throwable thrown) {
    try
    {
      ProxyConfig proxyConfig = getConfig();
      String filename = proxyConfig.getLogFile();
      boolean okToLog = filename != null && !filename.isEmpty() && logger != null;
      synchronized (_lockobject)
      {
        if (okToLog)
        {
          if (logger.getUseParentHandlers())
          {
            FileHandler fh = new FileHandler(filename, true);
            logger.addHandler(fh);
            SimpleFormatter formatter = new SimpleFormatter();
            fh.setFormatter(formatter);
            logger.setUseParentHandlers(false);

            String logLevelStr = proxyConfig.getLogLevel();
            Level logLevel = Level.SEVERE;

            if (logLevelStr != null)
            {
              try
              {
                logLevel = Level.parse(logLevelStr);
              } catch (IllegalArgumentException e)
              {
                SimpleDateFormat dt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                System.err.println(dt.format(new Date()) + ": " + logLevelStr + " is not a valid logging level.  Defaulting to SEVERE.");
              }
            }
            logger.setLevel(logLevel);

            logger.info("Log handler configured and initialized.");
          }

          if (thrown != null){
            logger.log(level, s, thrown);
          } else {
            logger.log(level, s);
          }
        }
      }
    }
    catch (Exception e)
    {
      SimpleDateFormat dt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      System.err.println("Error writing to log: ");
      System.err.println(dt.format(new Date()) + " " + s);
      e.printStackTrace();
    }
  }

  private static void _log(String s, Throwable thrown){
    _log(Level.SEVERE, s, thrown);
  }

  private static void _log(Level level, String s){
    _log(level, s, null);
  }

  private static Object _rateMapLock = new Object();

  private static void sendErrorResponse(HttpServletResponse response, String errorDetails, String errorMessage, int errorCode) 
      throws IOException
  {
    response.setHeader("Content-Type", "application/json");
    String message = "{" +
            "\"error\": {" +
            "\"code\": " + errorCode + "," +
            "\"details\": [" +
            "\"" + errorDetails + "\"" +
            "], \"message\": \"" + errorMessage + "\"}}";

    response.setStatus(errorCode);
    OutputStream output = response.getOutputStream();

    output.write(message.getBytes());

    output.flush();
  }

  private static void _sendURLMismatchError(HttpServletResponse response, String attemptedUri) 
      throws IOException
  {
    sendErrorResponse(response, 
        "Proxy has not been set up for this URL. Make sure there is a serverUrl in the "
            + "configuration file that matches: " + attemptedUri,
        "Proxy has not been set up for this URL.", 
        HttpServletResponse.SC_FORBIDDEN);
  }

  private static void _sendPingMessage(HttpServletResponse response, String version, String config, String log) 
      throws IOException
  {
    response.setStatus(HttpServletResponse.SC_OK);
    response.setHeader("Content-Type", "application/json");
    String message = "{ " +
        "\"Proxy Version\": \"" + version + "\"" +
        //", \"Java Version\": \"" + System.getProperty("java.version") + "\"" +
        ", \"Configuration File\": \"" + config + "\""  +
        ", \"Log File\": \"" + log + "\"" +
        "}";
    OutputStream output = response.getOutputStream();
    output.write(message.getBytes());
    output.flush();
  }  
}
