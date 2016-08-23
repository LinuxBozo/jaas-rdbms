// $Id: DBLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package com.tagish.auth;

import java.util.Map;
import java.util.*;
import java.sql.*;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


/**
 * Simple database based authentication module.
 *
 */
public class UAALogin extends SimpleLogin
{
	protected String                dbDriver;
	protected String                dbURL;
	protected String                dbUser;
	protected String                dbPassword;
	protected String                userTable;
	protected String                userColumn;
	protected String                passColumn;
	protected String 				originColumn;
	protected String 				idpOrigin;
	protected String                where;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	protected synchronized Vector validateUser(String username, char password[]) throws LoginException
	{
		ResultSet rsu = null, rsr = null;
		Connection con = null;
		PreparedStatement psu = null;

		try
		{
			Class.forName(dbDriver);
			if (dbUser != null)
			   con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
			else
			   con = DriverManager.getConnection(dbURL);
			psu = con.prepareStatement("SELECT " + passColumn + ", " + originColumn + " FROM " + userTable +
									   " WHERE " + userColumn + "=?" + where);

			/* Set the username to the statement */
			psu.setString(1, username);
			rsu = psu.executeQuery();
			if (!rsu.next()) throw new FailedLoginException("Unknown user");
			String db_pwd = rsu.getString("password");
			String db_origin = rsu.getString(originColumn).trim();
			String in_pwd = new String(password);
			System.err.println("Origin:   " + db_origin);

			/* Check the password */
			if (!passwordEncoder.matches(in_pwd, db_pwd)) throw new FailedLoginException("Bad password");
			psu.close();

			if (db_origin.equalsIgnoreCase("uaa")) {
				System.err.println("UAA user!");
				psu = con.prepareStatement("UPDATE " + userTable + " SET " + originColumn + "=?" +
											" WHERE " + userColumn + "=?");
				psu.setString(1, idpOrigin);
				psu.setString(2, username);
				int rowsUpdated = psu.executeUpdate();
				System.err.println("Updated " + rowsUpdated + " user(s)");
				psu.close();
			}

			Vector p = new Vector();
			p.add(new TypedPrincipal(username, TypedPrincipal.USER));
			return p;
		}
		catch (ClassNotFoundException e)
		{
			throw new LoginException("ClassNotFoundException: Error reading user database (" + e.getMessage() + ")");
		}
		catch (SQLException e)
		{
			throw new LoginException("SQLException: Error reading user database (" + e.getMessage() + ")");
		}
		finally
		{
			try {
				if (rsu != null) rsu.close();
				if (rsr != null) rsr.close();
				if (psu != null) psu.close();
				if (con != null) con.close();
			} catch (Exception e) { }
		}
	}

	public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options)
	{
		super.initialize(subject, callbackHandler, sharedState, options);

		dbDriver = getOption("dbDriver", null);
		if (dbDriver == null) throw new Error("No database driver named (dbDriver=?)");
		dbURL = getOption("dbURL", null);
		if (dbURL == null) throw new Error("No database URL specified (dbURL=?)");
		dbUser = getOption("dbUser", null);
		dbPassword = getOption("dbPassword", null);
		if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null))
		   throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");

		userTable    = getOption("userTable",    "users");
		userColumn   = getOption("userColumn", "username");
		passColumn   = getOption("passColumn",    "password");
		originColumn = getOption("originColumn",	"origin");
		idpOrigin	 = getOption("idpOrigin", "uaa");

		where        = getOption("where",        "");
		if (null != where && where.length() > 0)
			where = " AND " + where;
		else
			where = "";
	}

}
