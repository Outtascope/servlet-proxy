/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.esri.proxy.servlet;

/**
 *
 * @author Christopher C. Perry &lt;perrych2@msu.edu&gt;
 */
public class Constants {
  /** Application version identifier */
  public static final String VERSION = "1.0 Alpha";
  
  /** Default OAUTH endpoint to use */
  public static final String DEFAULT_OAUTH = "https://www.arcgis.com/sharing/oauth2/";
  
  /** Default referer (sic) */
  public static final String DEFAULT_PROXY_REFERER = "http://localhost/proxy.jsp";
  
  /** Content type string for html. */
  public static final String CONTENT_TYPE_HTML = "text/html;charset=UTF-8";
  
  /** UTF-8 Encoding Parameter */
  public static final String ENCODING_UTF8 = "UTF-8";
  
  public static final String ENCODED_HTTP = "http%3a%2f%2f";

  public static final String ENCODED_HTTPS = "https%3a%2f%2f";
  
  public static final String ATR_REFERER = "referer";
  public static final String ATR_RATEMAP = "rateMap";
  public static final String ATR_RATEMAPCC = "rateMap_cleanup_counter";
  public static final String CMD_PING = "ping";
  
  public static final String MSG_NULL_REFERER = "Proxy is being called by a null referer.  Access denied.";
  
  public static final String MSG_INVALID_REFERER = "Proxy is being used from an invalid referer: ";
  
  public static final String MSG_MISSING_REFERER = "Current proxy configuration settings do not allow requests which do not include a referer header.";
  public static final String MSG_VERIFY_REF_FAIL = "Error verifying referer. ";
  public static final String MSG_UNSUPPORTED_SERVICE = "Proxy is being used for an unsupported service: ";
  public static final String MSG_ACCESS_DENIED = "403 - Forbidden: Access is denied.";
  
  public static final String MSG_UNKNOWN_REFERER = "Proxy is being used from an unknown referer: ";
  
  public static final String MSG_UNSUPPORTED_REFERER = "Unsupported referer. ";
  
  public static final String MSG_RATELIMIT = "Pair %s$ is throttled to %d$ requests per %d$ minute(s). "
                                             + "Come back later.";
  public static final String MSG_OK = "OK";
  
  public static final String MSG_NOTREADABLE = "Not Readable";
  
  public static final String MSG_DOESNTEXIST = "Not Exist/Readable";
  
  public static final String MSG_CREATING = "Creating request for ";
  
  public static final String MSG_NOEMPTYPARAMS = "This proxy does not support empty parameters.";

  public static final String MSG_400PREFIX = "400 - ";
  
}
