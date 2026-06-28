import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

// 样本: 不安全的反序列化 - Java ObjectInputStream
// 期望: 检测到不安全的反序列化（直接 ObjectInputStream.readObject 处理用户数据）
public class SessionServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String sessionBlob = req.getParameter("session");
        byte[] data = Base64.getDecoder().decode(sessionBlob);
        // 漏洞：直接反序列化用户提供的对象
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            Object obj = ois.readObject();
            resp.getWriter().write(obj.toString());
        } catch (ClassNotFoundException e) {
            throw new IOException(e);
        }
    }
}
