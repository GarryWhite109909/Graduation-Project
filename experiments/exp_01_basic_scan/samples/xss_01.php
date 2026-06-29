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
</body>
</html>
