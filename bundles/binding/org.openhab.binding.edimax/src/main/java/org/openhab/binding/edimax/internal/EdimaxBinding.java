/**
 * Copyright (c) 2010-2015, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.edimax.internal;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Map;

import org.openhab.binding.edimax.EdimaxBindingProvider;
import org.openhab.binding.edimax.internal.EdimaxBindingConfiguration.Type;		// EdimaxBindingConfiguration.java
//																				// 	enum Type {	POWER, CURRENT, STATE}

import org.openhab.core.binding.AbstractActiveBinding;

import org.openhab.core.library.types.DecimalType;
import org.openhab.core.library.types.OnOffType;
import org.openhab.core.types.Command;
import org.openhab.core.types.State;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Binding main class.
 * 
 * @author Heinz
 *
 */
public class EdimaxBinding extends AbstractActiveBinding<EdimaxBindingProvider> {

	/**
	 * Logger.
	 */
	private static final Logger logger = LoggerFactory
			.getLogger(EdimaxBinding.class);

	/**
	 * Real devices discovered.
	 */
	private EdimaxDevice[] discoveredDevices;

	/**
	 * How many exception occur until it is considered to be a real error.
	 * Should be used in conjunction with {@link #getRefreshInterval()}. May
	 * also be configurable by managed service.
	 */
	private static final int EXCEPTION_COUNT_TO_REAL_ERROR = 4;

	/**
	 * How many errors occured in succession.
	 */
	private int errorCount;

	@Override
	protected void execute() {

		// discover
		if (shouldDiscover()) {
			discover();
		}

		// check device's state -> post if it changed.
		for (EdimaxBindingProvider provider : providers) {
			for (String itemName : provider.getItemNames()) {
				EdimaxBindingConfiguration config = ((EdimaxGenericBindingProvider) provider).getConfig(itemName);
				String macAddress = config.getMacAddress();
				String deviceIP = getDeviceIP(macAddress);
				logger.error("Device MAC=" + macAddress + " and  IP=" + deviceIP );  // 15okt24 Ptro debugging why config is not passed

				// if (deviceIP === null) {				// 15okt24 ptro == null
				if (deviceIP.equals(null)) {
					logger.error("Device with MAC: " + macAddress
							+ " not found/discovered.");
					continue;
				}

				// if type is null, default type is STATE
				EdimaxBindingConfiguration.Type type = config.getType();

				// if (type === null) {						// 15okt24 ptro == null
				if (type.equals(null)) {
					type = Type.STATE;
				}

				State newState = null;
				logger.debug("execute:" + type + " on " + deviceIP + " with password " 
							+ config.getPassword() + ", ip=" + getDeviceIP(macAddress) ) ;  // 15okt24 Ptro test edimax access

				// If finally block is present, it will be executed followed by the default handling mechanism. 

				try {
					switch (type) {
					case CURRENT:
						BigDecimal current = createSender(config).getCurrent(
								deviceIP);
						newState = new DecimalType(current);
						break;
					case POWER:
						BigDecimal power = createSender(config).getPower(
								deviceIP);
						newState = new DecimalType(power);
						break;
					case STATE:	// --> GetState.java
						// uses ../commands/GetState.java to fill in list.add("Device.System.Power.State");
                        // HTTPSend.java Boolean getState(String anIp) 
						//		--> AbstractCommand.java:  executeCommand throws IOException
						//			--> AbstractCommand.java: HTTPSend.java: HTTPSend.executePost(ci.getUrl(),
						//  				ci.getPort(),lastPart, getCommandString(), ci.getUsername(),ci.getPassword());
						// 
						// ConnectionInformation ci = new ConnectionInformation(defaultUser,password, completeUrl, PORT);
						//  HTTPSend createSender(EdimaxBindingConfiguration config)
						Boolean state = createSender(config).getState(deviceIP);
						if (state) {
							newState = OnOffType.ON;
						} else {
							newState = OnOffType.OFF;
						}
						break;
					}
				} catch (IOException e) {

					// 2024-10-15 21:41:36.035 [DEBUG] [inding.edimax.internal.EdimaxBinding] HTTPSend- wr.write(urlParameters.getBytes()); done & closed                                                                
					// 2024-10-15 21:41:36.064 [DEBUG] [inding.edimax.internal.EdimaxBinding] HTTPSend- executePost: try finally connection.disconnect()                                                                 
					// 2024-10-15 21:41:36.108 [ERROR] [inding.edimax.internal.EdimaxBinding] - Error in communication with device. Device's MAC: 74DA384B1757. Cannot get update from device.                   

					//  createSender(config).getState(deviceIP); --> we get a HTTP 401 see below for exact error message
					// java.io.IOException: Server returned HTTP response code: 401 for URL: http://192.168.1.130:10000/smartplug.cgi 

					logger.error(
							"Error in communication with device. Device's MAC: "
									+ macAddress
									+ ". Cannot get update from device.", e);
					logger.debug("IOException: try execute: IP" + getDeviceIP(macAddress)); 	 // 15okt24 Ptro debugging why config is not passed
					// 2024-10-15 19:48:18.801 [DEBUG] [inding.edimax.internal.EdimaxBinding] - finally: try executeorg.openhab.binding.edimax.internal.EdimaxBindingConfiguration@164effc 
				// ptro 15okt24: added to check and find out how finally is behaving
				} finally {
					logger.debug("finally: try execute, IP:" + getDeviceIP(macAddress));
					// 2024-10-15 19:48:18.802 [DEBUG] [inding.edimax.internal.EdimaxBinding] - after: try executeorg.openhab.binding.edimax.internal.EdimaxBindingConfiguration@164effc 
				}
				logger.debug("after: try execute" + config );	 // 15okt24 Ptro debugging why config is not passed

				if (newState != null) {
					eventPublisher.postUpdate(itemName, newState);
				}
			}
		}
	}

	/**
	 * Creates sender based on the configured password.
	 * 
	 * @param config
	 * @return
	 */
	private HTTPSend createSender(EdimaxBindingConfiguration config) {
		String password = config.getPassword();
        // password = "edimax001"; 					// 15okt24 ptro force password
		// if (password === null) {
        logger.debug("CreateSender HTTPSend password =" + password );  // 15okt24 Ptro debugging why config is not passed
		if (password.equals(null)) {
			return new HTTPSend();				// HTTPSend.java
		} else {
			return new HTTPSend(password);		// HTTPSend.java
		}
	}

	/**
	 * Discovery tool.
	 */
	private Discoverer discoverer = new UDPDiscoverer();

	/**
	 * Discovery.
	 */
	protected void discover() {
		logger.debug("Edimax discovery running.");
		EdimaxDevice[] discovered = null;
		try {
			discovered = discoverer.discoverDevices();
			// no error present - all fine
			errorCount = 0;
			discoveredDevices = discovered;
		} catch (DiscoveryException e1) {
			// errors may occur
			errorCount++;
			if (errorCount >= EXCEPTION_COUNT_TO_REAL_ERROR) {
				// real error occured - set current devices to those
				discoveredDevices = discovered;
				logger.error(
						"Error discovering Edimax devices. Amount of exceptions: "
								+ EXCEPTION_COUNT_TO_REAL_ERROR, e1);
			} else {
				logger.debug("Interim error discovering Edimax devices.", e1);
			}
		}
	}

	/**
	 * Discover step counter.
	 */
	private int discoverStep = 0;

	/**
	 * The amount of executes() which are skipped until another discover
	 * happens. @See #getRefreshInterval.
	 */
	private static final int DISCOVER_SKIP_STEP = 60;

	/**
	 * Checks whether to discover or not (not always discover when thread runs).
	 * 
	 * @return
	 */
	protected boolean shouldDiscover() {
		boolean doDiscover = false;
		if (discoverStep % DISCOVER_SKIP_STEP == 0) {
			doDiscover = true;
			discoverStep = 0; // under- overrun
		}

		discoverStep++;
		return doDiscover;
	}

	private String getDeviceIP(String aMac) {
		aMac = aMac.toUpperCase();
		for (EdimaxDevice device : discoveredDevices) {
			if (aMac.equals(device.getMac())) {
				logger.debug("getDeviceIP Mac=" + aMac + ", DeviceIP=" + device.getIp() );
				return device.getIp();
			}
		}
		return null;
	}

	@Override
	protected void internalReceiveCommand(String itemName, Command command) {
		for (EdimaxBindingProvider provider : providers) {
			EdimaxBindingConfiguration config = ((EdimaxGenericBindingProvider) provider)
					.getConfig(itemName);
			String deviceIP = getDeviceIP(config.getMacAddress());
			// if (deviceIP === null) {			// 15okt24 ptro == null
			if (deviceIP.equals(null)) {
				logger.debug("No real device for item: " + itemName + " found.");
				continue;
			}
			changeValue(itemName, deviceIP, config, command);
			break;
		}
	}

	private void changeValue(String itemName, String deviceIP,
			EdimaxBindingConfiguration config, Command cmd) {
		if (cmd instanceof OnOffType) {
			try {
				Boolean currentState = createSender(config).getState(deviceIP);
				OnOffType targetState = (OnOffType) cmd;
				if (targetState == OnOffType.ON && !currentState) {
					createSender(config).switchState(deviceIP, Boolean.TRUE);
				} else if (targetState == OnOffType.OFF && currentState) {
					createSender(config).switchState(deviceIP, Boolean.FALSE);
				}

			} catch (IOException e) {
				logger.error("Error in communication with device: " + itemName
						+ ". Cannot set update to device.", e);
			}

		} else {
			logger.error("Unsupported command: " + cmd);
		}
	}

	/**
	 * Called by SCR to activate component.
	 * 
	 * @param bundleContext
	 * @param configuration
	 */
	public void activate(final BundleContext bundleContext,
			final Map<String, Object> configuration) {
		setProperlyConfigured(true);
	}

	@Override
	protected long getRefreshInterval() {
		// once every 30 seconds.
		return 1000 * 30;
	}

	@Override
	protected String getName() {
		return "Edimax update/discovery";
	}

}



/*
java.net.HttpURLConnection.HTTP_UNAUTHORIZED
see: [https://http.dev/401] , this returns: the WWW-Authenticate response header
		<-- WWW-Authenticate: Digest realm="SP1101W", nonce="1845ce45bd3a5dac6fe01105c63bc416", qop="auth"
		= HTTP Digest access authentication is a challenge-response protocol that can be used to authenticate resource requests RFC 7616

error messages:

2024-10-15 04:10:00.622 [DEBUG] [inding.edimax.internal.EdimaxBinding] - getPassword: return password=edimax001. 
 024-10-15 04:10:00.623 [DEBUG] [inding.edimax.internal.EdimaxBinding] (--> HTTPSend) complete=http://192.168.1.130:10000/smartplug.cgiurlParameters=<?xml version="1.0" encoding="UTF8"?>
<SMARTPLUG id="edimax"><CMD id="get"><Device.System.Power.State/></CMD></SMARTPLUG> 

2024-10-15 04:10:00.624 [DEBUG] [inding.edimax.internal.EdimaxBinding] - basicAuth=admin:edimax001, cod64=Basic YWRtaW46ZWRpbWF4MDAx 
2024-10-15 04:10:00.625 [DEBUG] [inding.edimax.internal.EdimaxBinding] - HttpURLConnection=sun.net.www.protocol.http.HttpURLConnection:http://192.168.1.130:10000/smartplug.cgi 

2024-10-15 04:10:00.658 [ERROR] [inding.edimax.internal.EdimaxBinding] - Error in communication with device. Device's MAC: 74DA384B1757. Cannot get update from device. 
java.io.IOException: Server returned HTTP response code: 401 for URL: http://192.168.1.130:10000/smartplug.cgi 
        at sun.net.www.protocol.http.HttpURLConnection.getInputStream0(HttpURLConnection.java:1876) ~[?:?] 
        at sun.net.www.protocol.http.HttpURLConnection.access$200(HttpURLConnection.java:91) ~[?:?] 
        at sun.net.www.protocol.http.HttpURLConnection$9.run(HttpURLConnection.java:1466) ~[?:?] 
        at sun.net.www.protocol.http.HttpURLConnection$9.run(HttpURLConnection.java:1464) ~[?:?] 
        at java.security.AccessController.doPrivileged(Native Method) ~[?:?] 
        at java.security.AccessController.doPrivilegedWithCombiner(AccessController.java:782) ~[?:?] 
        at sun.net.www.protocol.http.HttpURLConnection.getInputStream(HttpURLConnection.java:1463) ~[?:?] 
        at org.openhab.binding.edimax.internal.HTTPSend.executePost(HTTPSend.java:203) ~[343:org.openhab.binding.edimax:1.14.0.202410150202] 
        at org.openhab.binding.edimax.internal.commands.AbstractCommand.executeCommand(AbstractCommand.java:216) ~[343:org.openhab.binding.edimax:1.14.0.202410150202] 
        at org.openhab.binding.edimax.internal.HTTPSend.getState(HTTPSend.java:102) ~[343:org.openhab.binding.edimax:1.14.0.202410150202] 
        at org.openhab.binding.edimax.internal.EdimaxBinding.execute(EdimaxBinding.java:106) [343:org.openhab.binding.edimax:1.14.0.202410150202] 
        at org.openhab.core.binding.AbstractActiveBinding$BindingActiveService.execute(AbstractActiveBinding.java:144) [218:org.openhab.core.compat1x:2.4.0] 
        at org.openhab.core.service.AbstractActiveService$RefreshThread.run(AbstractActiveService.java:166) [218:org.openhab.core.compat1x:2.4.0] 

2024-10-15 04:10:30.661 [DEBUG] [inding.edimax.internal.EdimaxBinding] - getDeviceIP Mac=74DA384B1757, DeviceIP=192.168.1.130 
2024-10-15 04:10:30.662 [ERROR] [inding.edimax.internal.EdimaxBinding] - Device MAC=74DA384B1757 and  IP=192.168.1.130 
2024-10-15 04:10:30.663 [DEBUG] [inding.edimax.internal.EdimaxBinding] - getPassword: return password=edimax001
*/
