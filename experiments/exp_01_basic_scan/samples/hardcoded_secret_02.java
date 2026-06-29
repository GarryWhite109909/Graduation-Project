import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConfig {

    private static final String DB_URL = "jdbc:mysql://prod-db.internal:3306/users";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "P@ssw0rd_2024!Admin";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}
