package com.appbootup.gwt.server.filter;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.owasp.esapi.ESAPI;

public class XSSRequestWrapper extends HttpServletRequestWrapper
{

	private static Pattern[] patterns = new Pattern[]
	{
			// Script fragments
	Pattern.compile( "<script>(.*?)</script>", Pattern.CASE_INSENSITIVE ),
			// src='...'
	Pattern.compile( "src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL ), Pattern
			.compile( "src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL ),
			// lonely script tags
	Pattern.compile( "</script>", Pattern.CASE_INSENSITIVE ), Pattern
			.compile( "<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL ),
			// eval(...)
	Pattern.compile( "eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL ),
			// expression(...)
	Pattern.compile( "expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL ),
			// javascript:...
	Pattern.compile( "javascript:", Pattern.CASE_INSENSITIVE ),
			// vbscript:...
	Pattern.compile( "vbscript:", Pattern.CASE_INSENSITIVE ),
			// onload(...)=...
	Pattern.compile( "onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL ),
			// onerror(...)=...
	Pattern.compile( "onerror(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL ) };

	public XSSRequestWrapper( HttpServletRequest servletRequest )
	{
		super( servletRequest );
	}

	@Override
	public String[] getParameterValues( String parameter )
	{
		String[] values = super.getParameterValues( parameter );

		if ( values == null )
		{
			return null;
		}

		int count = values.length;
		String[] encodedValues = new String[count];
		for ( int i = 0; i < count; i++ )
		{
			encodedValues[i] = stripXSS( values[i] );
		}

		return encodedValues;
	}

	@Override
	public String getParameter( String parameter )
	{
		String value = super.getParameter( parameter );

		return stripXSS( value );
	}

	@Override
	public String getHeader( String name )
	{
		String value = super.getHeader( name );
		return stripXSS( value );
	}

	/**
	 * Escape an html string. Escaping data received from the client helps to
	 * prevent cross-site script vulnerabilities.
	 *
	 * @param html the html string to escape
	 * @return the escaped string
	 */
	public static String escapeHtml( String html )
	{
		if ( html == null )
		{
			return null;
		}
		return html.replaceAll( "&", "&amp;" ).replaceAll( "<", "&lt;" )
				.replaceAll( ">", "&gt;" );
	}

	public static String stripXSS( String value )
	{
		if ( value != null )
		{
			// NOTE: It's highly recommended to use the ESAPI library and uncomment the following line to
			// avoid encoded attacks.
			value = ESAPI.encoder().canonicalize( value );

			// Avoid null characters
			value = value.replaceAll( "\0", "" );

			// Remove all sections that match a pattern
			for ( Pattern scriptPattern : patterns )
			{
				Matcher matcher = scriptPattern.matcher( value );
				value = matcher.replaceAll( "" );
			}
		}
		return value;
	}
}