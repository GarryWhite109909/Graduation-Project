import java.sql.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class LoginSafeServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        try (Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/test", "root", "root")) {
            String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, username);
            stmt.setString(2, password);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                resp.getWriter().println("Login success");
            } else {
                resp.getWriter().println("Invalid");
            }
        } catch (SQLException e) {
            resp.getWriter().println("DB error");
        }
    }
}
