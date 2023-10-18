import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.ResultSet;


class PasswordManager {
    
    private static final String ENCODING = "UTF-8"; // Current key with invalid length
    private static final String FIXED_KEY = "Infotrixs@Key123";
    static Scanner scanner = new Scanner(System.in); 
    private Cipher cipher;
    // private SecretKeySpec secretKey;
    public PasswordManager() throws NoSuchAlgorithmException, NoSuchPaddingException {
        // Initialize the cipher here
        this.cipher = Cipher.getInstance("AES");
    }
    
    private SecretKeySpec deriveKey(String masterPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Use PBKDF2 to derive a cryptographic key from the master password
        

        byte[] salt = "SALT_FOR_PBKDF2".getBytes();
        int iterationCount = 65536;
        int keyLength = 256;

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt, iterationCount, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }
    
    
    private String encrypt(String password, String masterPassword) throws Exception {
    SecretKeySpec secretKey = deriveKey(masterPassword);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    byte[] encryptedBytes = cipher.doFinal(password.getBytes(ENCODING));
    return Base64.getEncoder().encodeToString(encryptedBytes);
}

private String decrypt(String encryptedPassword, String masterPassword) throws Exception {
    SecretKeySpec secretKey = deriveKey(masterPassword);
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPassword);
    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
    return new String(decryptedBytes, ENCODING);
}


public void registerUser()
    {

        System.out.println("\n\t\t\tWelcome to User Registration!");

        System.out.print("Enter a username:");
        String username = scanner.next();

        String masterPassword=null;
        System.out.print("\nDo you wish to for us to generate a strong password? (Y/N)");
        String recc=scanner.next();
        if(recc.equalsIgnoreCase("Y"))
        {
        System.out.println("personalize your Password:");
        System.out.print("Specify the length of the password between(8-16): ");
        int passlen=scanner.nextInt();

        System.out.print("\ninclude Uppercase? (Y/N)");
        boolean UpperCase=(scanner.next().equalsIgnoreCase("Y")?true:false);
        System.out.print("\ninclude lowercase? (Y/N)");
        boolean lowerCase=(scanner.next().equalsIgnoreCase("Y")?true:false);
        System.out.print("\ninclude digits? (Y/N)");
        boolean digits=(scanner.next().equalsIgnoreCase("Y")?true:false);
        System.out.print("\ninclude special Characters? (Y/N)");
        boolean  spChar=(scanner.next().equalsIgnoreCase("Y")?true:false);
       
           masterPassword= generatePassword(passlen, UpperCase, lowerCase, digits, spChar);
            System.out.println("\n\nThis is your master password : "+masterPassword);
        }
        else
        {
            
             boolean strength=false;
             while(strength==false)
            {    System.out.print("Enter a master password:");
                masterPassword = scanner.next();
                strength=isPasswordStrongEnough(masterPassword);
                if(isPasswordStrongEnough(masterPassword)==false)
                {
                System.out.println("\nPassword must contain atleast one Uppercase,Lower Case,\n" +
                        "a number and a special charachter and must be of 8-16 characters length.");
                }
            }
        }
        
        String encryptedPassword=null;
        try{
            encryptedPassword = encrypt(masterPassword, FIXED_KEY);
              
        }catch(Exception e)
        {
            System.out.println(e.getMessage());
        }
        insertUserIntoUserTable(username,encryptedPassword);

        
        
        loginUser();
    }
    public void loginUser()
    {   
        System.out.println("\n\n\t\t\tWelcome To Login page");
        //contains code for Login of the user
        System.out.print("\nEnter Username: ");
        String username=scanner.next();

        System.out.print("\nEnter Master Password:");
        String password=scanner.next();
        
        try{
           
        if(password.equals(decrypt(checkPasswordFromDatabase(username),FIXED_KEY)))
        {
            System.out.println("\nuser Login successfull\n\n");
            
            Welcome(username,password);

        }
        else
        {
            System.out.println("username or password Incorrect, Please try again:");
            loginUser();
        }
    }
    catch(Exception e)
    {
        System.out.println("Username or password incorrect.\n");
        System.out.println("Do you want to continue with login? (Y/N)");
        
        String recc=scanner.next();
        if(recc.equalsIgnoreCase("Y"))
        {
        loginUser();
        }
        else
        {
            System.out.println("Thanks for using our application");
        }
        
    }
        

    }
    public void exit()
    {
        System.out.println("\nThanks for using this application!!");
    }

    private Connection connectToDatabse()
    {   //creation of database
        //SQL operations performed here 
        String url="jdbc:sqlite:Database.db";
        Connection connection=null;
        try{
        connection=DriverManager.getConnection(url); 
        
        
        }
        catch(SQLException e){
            System.out.println(e.getMessage());
        }
        return connection;
        
    }
    
    public void createUsersTableIfNotExist()
    {
        String createTable="CREATE TABLE IF NOT EXISTS profiles(\n"
        +"userid varchar PRIMARY KEY,\n"
        +"gmail_username varchar,"
        +"password varchar,"
        +"fb_username varchar,"
        +"fb_password varchar,"
        +"insta_username varchar,"
        +"insta_password varchar"
        +");";
        String createUserTable="CREATE TABLE IF NOT EXISTS users(\n"
        +"userid varchar PRIMARY KEY,\n"
        +"password varchar NOT NULL)";
        //String dropTable="DROP TABLE users";
        Connection conn=null;
        try{
            conn=this.connectToDatabse();
            Statement stmt=conn.createStatement();
            stmt.execute(createUserTable);
            stmt.execute(createTable);
        }
        catch(SQLException e)
        {
            System.out.println(e.getMessage());
        }
        finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                System.out.println(ex.getMessage());
            }
        }
    }
    public void insertUserIntoUserTable(String userid,String password)
    {
        String insertUser="INSERT INTO users (userid,password) Values(?,?)";
        Connection conn=null;
        try 
        {
            conn=this.connectToDatabse();
            PreparedStatement pstmt=conn.prepareStatement(insertUser);
            pstmt.setString(1, userid);
            pstmt.setString(2, password);
            pstmt.executeUpdate();
            System.out.println("\n\nUser registered successfully!");

        } 
        catch (SQLException e) 
        {
            System.out.println("\nuser already exist");
            
        }finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                System.out.println(ex.getMessage());
            }
        }
    }

    public String checkPasswordFromDatabase(String username)
    { String sql = "SELECT password FROM users WHERE userid='"+username+"';";
        Connection conn=null;
        try {
            conn=this.connectToDatabse();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                String value = rs.getString("password");
                return value;
            }
        } catch (Exception e) {
            System.out.println("Line 190 "+e.getMessage());
        }
        finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                System.out.println(ex.getMessage());
            }
        }
        return null;
    }

     public void Welcome(String username,String masterPassword)
    {
        //CLI interface Welcome Screen 
        //contains register,login,exit options
        boolean cont=true;
         System.out.println("\n\nHello "+username+"\n");
        System.out.println("which action do you wish to perform?");
        
        while(cont==true)
        {

        
        System.out.println("\n Chose one of these options");
        System.out.println("1.Store Password\n2.Retrieve Password\n3.Log out");
        System.out.print("\nEnter your choice: ");
        int ua=scanner.nextInt();
        switch (ua) {
            case 1:
                storePassword(username,masterPassword);
                break;
            case 2:
                retrievePassword(username,masterPassword);
                break;
            case 3:
                System.out.print("\nLog out and Exit? (Y/N) ");
                String logout=scanner.next();

                if(logout.equalsIgnoreCase("Y"))
                {
                    exit();
                    cont=false;
                }
                else
                {
                    loginUser();
                }
                break;
                
                 }   
         }

    }
    


    public void storePassword(String username,String masterPassword)
    {
        System.out.println("\n We have few pre-defined profiles you can store of ,They are:");
        System.out.println("1.Gmail\n2.Facebook\n3.Instagram\n4.Other");
        System.out.print("\nEnter your choice: ");
        int acc=scanner.nextInt();
        switch (acc) {
            case 1:
                userChoiceForStoringPassword(username,masterPassword,"gmail_username","password");
                break;
            case 2:
                userChoiceForStoringPassword(username, masterPassword,"fb_username","fb_password");
                break;
            case 3:
                userChoiceForStoringPassword(username, masterPassword,"insta_username", "insta_password");
                break;
            case 4:
                newColumnsDetails(username,masterPassword);
                break;
                
            
        }
    }

    public void newColumnsDetails(String username,String masterpassword)
    {
        System.out.print("Enter custom account name: ");
        String accName=scanner.next();
        String passAccName=accName+"_password";
        addColumnForOtherAccounts(accName, passAccName);
        userChoiceForStoringPassword(username,masterpassword, accName, passAccName);
    }
    public void userChoiceForStoringPassword(String username,String masterpassword,String columnname, String passColumnName)
    {
        System.out.print("\nEnter Username: ");
        String uname=scanner.next();
        System.out.print("\nEnter password: ");
        String Password=scanner.next();
        String encryptedPass=null;
        try {
            encryptedPass=encrypt(Password,masterpassword);
        } catch (Exception e) {
            System.out.println("LIne 262"+ e.getMessage());
        }
        insertPasswordsIntoUserTable(username,uname,columnname,passColumnName,encryptedPass);
    }


    public void insertPasswordsIntoUserTable(String userid,String uname,String columnName,String passColumnName,String password)
    {
        String insertUser="INSERT INTO profiles (userid,"+columnName+","+passColumnName+") Values(?,?,?)";
        Connection conn=null;
        try 
        {
            conn=this.connectToDatabse();
            PreparedStatement pstmt=conn.prepareStatement(insertUser);
            
            pstmt.setString(1,userid);
            pstmt.setString(2, uname);
            pstmt.setString(3, password);
            pstmt.executeUpdate();
            System.out.println("\npassword has been stored successfully!");

        } 
        catch (SQLException e) 
        {
            //System.out.println("line 284"+ e.getMessage());
            addPasswordsIfUserExistInProfiles(userid, uname, columnName, passColumnName, password);
            
        }finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                System.out.println(ex.getMessage());
            }
        }
    }
    
    public void addPasswordsIfUserExistInProfiles(String userid,String uname,String columnName,String passColumnName,String password)
    {
        String sql="UPDATE profiles SET "+ columnName+"='"+uname+"',"+passColumnName+"='"+password+"' WHERE userid='"+userid+"'";
        Connection conn=null;
        try {
            conn=this.connectToDatabse();
            Statement stmt=conn.createStatement();
            stmt.executeUpdate(sql);

            System.out.println("\nPassword has been Stored successfully!!");
        } catch (Exception e) {
            System.out.println("Line 411"+ e.getMessage());
            
        }finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                System.out.println(ex.getMessage());
            }
        }
    }
    
    public void addColumnForOtherAccounts(String columnName,String passColumnName)
    {
        String sql="ALTER TABLE profiles ADD COLUMN "+columnName+" varchar";
        String sql2="ALTER TABLE profiles ADD COLUMN "+passColumnName+" varchar";
        Connection conn=null;
        try {
            conn=this.connectToDatabse();
            Statement stmt=conn.createStatement();
            stmt.execute(sql);
            stmt.execute(sql2);
        } catch (Exception e) {
            
            System.out.println("");
        }finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                System.out.println(ex.getMessage());
            }
        }
    }
    private static boolean isPasswordStrongEnough(String password) {
        // Check if the password contains at least one uppercase letter, one lowercase letter, one digit, and one special character
        boolean hasUppercase = false;
        boolean hasLowercase = false;
        boolean hasDigit = false;
        boolean hasSpecialCharacter = false;

        for (char ch : password.toCharArray()) {
            if (Character.isUpperCase(ch)) {
                hasUppercase = true;
            } else if (Character.isLowerCase(ch)) {
                hasLowercase = true;
            } else if (Character.isDigit(ch)) {
                hasDigit = true;
            } else {
                hasSpecialCharacter = true;
            }
        }

        return hasUppercase && hasLowercase && hasDigit && hasSpecialCharacter;
    }
   

    public void retrievePassword(String username,String masterPassword)
    {
        System.out.println("\nWhich Password you want to retrieve: ");
        System.out.println("1.Gmail \n2.facebook\n3.Instagram\n4.Other");
        System.out.print("Enter your choice: ");
        int ret=scanner.nextInt();
        switch (ret) {
            case 1:
                userChoiceForRetrieving(username,masterPassword, "gmail_username", "password");
                break;
            case 2:
                userChoiceForRetrieving(username,masterPassword, "fb_username", "fb_password");
                break;
            case 3:
                userChoiceForRetrieving(username,masterPassword, "insta_username", "insta_password");
                break;
            case 4:
                userChoiceForRetrievingOthers(username,masterPassword);
                break;
        }
        //retrieving the data(passwords and labels) from database using getDatabase
        //must come from decrypt()
    }
    public void userChoiceForRetrievingOthers(String username,String masterPassword)
    {
        System.out.println("\nProfile name:");
        String otherProfName=scanner.next();
        String otherProfPass=otherProfName+"_password";
        userChoiceForRetrieving(username,masterPassword, otherProfName, otherProfPass);
    }

   public void userChoiceForRetrieving(String username,String masterPassword,String columnName,String passColumnName)
    {
        String uname=userChoiceForRetrievingUsername(username, columnName);
        if(uname==null)
        {
            System.out.println("\nUser Id and password Doesn't exist.");
        }
        else{
        String profile_username=uname;
        String profile_password=null;
        try {
            profile_password=decrypt(userChoiceForRetrievingPassword(username, passColumnName),masterPassword);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        
        System.out.println("username: "+profile_username+"\nPassword: "+profile_password);
    }
    }

    public String userChoiceForRetrievingUsername(String username,String columnName)
    {
        String sql="SELECT "+columnName+" From profiles WHERE userid='"+username+"'";
        Connection conn=null;
        try {
            conn=this.connectToDatabse();
            Statement stmt=conn.createStatement();
            ResultSet res=stmt.executeQuery(sql);
            if (res.next()) {
                
                String value = res.getString(columnName);
            
                return value;
            }

        } catch (Exception e) {
          
            System.out.println("line 496"+e.getMessage());
        }finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                System.out.println(ex.getMessage());
            }
        }
        return null;
    }

    public String userChoiceForRetrievingPassword(String username,String passColumnName)
    {
        String sql="SELECT "+passColumnName+" From profiles WHERE userid='"+username+"'";
        Connection conn=null;
        try {
            conn=this.connectToDatabse();
            Statement stmt=conn.createStatement();
            ResultSet res=stmt.executeQuery(sql);
            if (res.next()) {
                
                String value = res.getString(passColumnName);
            
                return value;
            }

        } catch (Exception e) {
          
            System.out.println("line 489"+e.getMessage());
        }finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                System.out.println(ex.getMessage());
            }
        }
        return null;
    }


 public void menuInterface()
 {
    System.out.println("\t\t\t Welcome to Password Manager");
    System.out.println("1.Register User \n2.Login User \n3.Exit");
    System.out.print("Enter your choice: ");
    int UI=scanner.nextInt();
    switch (UI) {
        case 1:
            registerUser();
            break;
        case 2:
            loginUser();
            break;
        case 3:
            exit();
            break;
    }

 }
    public static void main(String[] args) throws Exception
    { 
        //java -classpath ".;sqlite-jdbc-3.42.0.0.jar" PasswordManager
        PasswordManager pm=new PasswordManager();
        pm.createUsersTableIfNotExist();
        pm.menuInterface();
        
        
        
        //class creation
        //calling userInterface method
    }


public String generatePassword(int length, boolean includeUppercase, boolean includeLowercase,
    boolean includeDigits, boolean includeSpecialCharacters) {
    String uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    String lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    String digitChars = "0123456789";
    String specialChars = "!@#$%^&*()_-+=<>?/{}[]";

    StringBuilder availableCharsBuilder = new StringBuilder();
    StringBuilder passwordBuilder = new StringBuilder();

    Random random = new Random();

if (includeUppercase) {
    availableCharsBuilder.append(uppercaseChars);
    passwordBuilder.append(uppercaseChars.charAt(random.nextInt(uppercaseChars.length())));
}
if (includeLowercase) {
    availableCharsBuilder.append(lowercaseChars);
    passwordBuilder.append(lowercaseChars.charAt(random.nextInt(lowercaseChars.length())));
}
if (includeDigits) {
    availableCharsBuilder.append(digitChars);
    passwordBuilder.append(digitChars.charAt(random.nextInt(digitChars.length())));
}
if (includeSpecialCharacters) {
    availableCharsBuilder.append(specialChars);
    passwordBuilder.append(specialChars.charAt(random.nextInt(specialChars.length())));
}

int availableCharsLength = availableCharsBuilder.length();

for (int i = passwordBuilder.length(); i < length; i++) {
    passwordBuilder.append(availableCharsBuilder.charAt(random.nextInt(availableCharsLength)));
}

// Shuffle the characters in the password
char[] passwordChars = passwordBuilder.toString().toCharArray();
for (int i = passwordChars.length - 1; i > 0; i--) {
    int index = random.nextInt(i + 1);
    char temp = passwordChars[index];
    passwordChars[index] = passwordChars[i];
    passwordChars[i] = temp;
}

return new String(passwordChars);
}

}



