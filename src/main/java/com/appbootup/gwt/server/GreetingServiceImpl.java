package com.appbootup.gwt.server;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import com.appbootup.gwt.client.GreetingService;
import com.appbootup.gwt.server.filter.XSSRequestWrapper;
import com.appbootup.gwt.shared.FieldVerifier;
import com.google.gwt.user.server.rpc.RemoteServiceServlet;

/**
 * The server side implementation of the RPC service.
 */
@SuppressWarnings( "serial" )
public class GreetingServiceImpl extends RemoteServiceServlet implements GreetingService
{

	@Override
	protected String readContent( HttpServletRequest request ) throws ServletException, IOException
	{
		String readContent = super.readContent( request );
		String readContentStripped = XSSRequestWrapper.stripXSS( readContent );
		return readContentStripped;
	}

	public String greetServer( String input ) throws IllegalArgumentException
	{
		// Verify that the input is valid.
		if ( !FieldVerifier.isValidName( input ) )
		{
			// If the input is not valid, throw an IllegalArgumentException back to
			// the client.
			throw new IllegalArgumentException( "Name must be at least 4 characters long" );
		}
		//match( input );
		String serverInfo = getServletContext().getServerInfo();
		String userAgent = getThreadLocalRequest().getHeader( "User-Agent" );

		// Escape data from the client to avoid cross-site script vulnerabilities.
		//String inputStripped = XSSRequestWrapper.stripXSS( input );
		//String inputEscaped = XSSRequestWrapper.escapeHtml( input );
		userAgent = XSSRequestWrapper.escapeHtml( userAgent );

		return "Hello, " + input + "!<br><br>I am running " + serverInfo + ".<br><br>It looks like you are using:<br>" + userAgent;
	}
}
