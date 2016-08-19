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
public class BCryptDBLogin extends SimpleLogin
{
	protected String                dbDriver;
	protected String                dbURL;
	protected String                dbUser;
	protected String                dbPassword;
	protected String                userTable;
	protected String                userColumn;
	protected String                passColumn;
	protected String                where;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4);

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

			psu = con.prepareStatement("SELECT " + passColumn + " FROM " + userTable +
									   " WHERE " + userColumn + "=?" + where);

			/* Set the username to the statement */
			psu.setString(1, username);
			rsu = psu.executeQuery();
			if (!rsu.next()) throw new FailedLoginException("Unknown user");
			String db_pwd = rsu.getString(1);
			String in_pwd = new String(password);

			String in_pwd_enc = passwordEncoder.encode(in_pwd);
			String in_pwd_enc2 = passwordEncoder.encode(in_pwd);

			/* Check the password */
			System.err.println("Database:  " + db_pwd);
			System.err.println("Entered:   " + in_pwd);
			System.err.println("Encrypted: " + in_pwd_enc);
			System.err.println("Matches DB:" + passwordEncoder.matches(in_pwd, db_pwd));
			System.err.println("Matches IN:" + passwordEncoder.matches(in_pwd, in_pwd_enc2));

			if (!passwordEncoder.matches(in_pwd, db_pwd)) throw new FailedLoginException("Bad password");

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

		userTable    = getOption("userTable",    "User");
		userColumn   = getOption("userColumn", "user_name");
		passColumn   = getOption("passColumn",    "user_passwd");
		where        = getOption("where",        "");
		if (null != where && where.length() > 0)
			where = " AND " + where;
		else
			where = "";
	}

}
