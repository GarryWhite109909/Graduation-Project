import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 样本: 路径穿越 - Java Servlet 读取文件
// 期望: 检测到路径穿越（用户输入直接构造 File，未过滤 ../）
public class FileDownloadServlet extends HttpServlet {

    private static final String BASE_DIR = "/var/www/files";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        // 漏洞：直接使用用户输入构造路径
        File file = new File(BASE_DIR + "/" + filename);
        if (!file.exists()) {
            resp.sendError(404);
            return;
        }
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buf = fis.readAllBytes();
            resp.getOutputStream().write(buf);
        }
    }
}
