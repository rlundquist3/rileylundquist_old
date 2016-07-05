<?php
$q=$_REQUEST["q"];

// lookup all hints from array if $q is different from ""
if ($q !== "") {
    $names = array();

    $files = scandir('/templates/images/'.$q);
    foreach($files as $file) {
        $names[] = $file;
    }

    echo json_encode($names);
}
?>
