<!-- 样本: XSS - PHP 直接输出用户输入 -->
<!-- 期望: 检测到反射型 XSS（用户输入未转义直接 echo 到 HTML） -->
<?php
$name = $_GET['name'] ?? '';
$comment = $_POST['comment'] ?? '';
?>
<!DOCTYPE html>
<html>
<head><title>Profile</title></head>
<body>
    <h1>Hello, <?php echo $name; ?></h1>
    <div class="comment"><?php echo $comment; ?></div>
    <!-- 漏洞：未使用 htmlspecialchars 转义 -->
</body>
</html>
