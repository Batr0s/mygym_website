<?php
require("../model/database.php");

$con = conectar();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];
    $password = $_POST['pass'];
    
    $consulta = valida_usuario($con, $email, $password);
    
    if(obtener_num_filas($consulta) == 1){
        $usuario = obtener_resultados($consulta);
        session_start();
        $_SESSION['id_user'] = $usuario['id'];
        $_SESSION['nombre_user'] = $usuario['name'];
        $_SESSION['type'] = $usuario['type'];
        
        if ($usuario['type'] == 0) {
         
            echo "../view/admin.php";
        } elseif ($usuario['type'] == 1) {
            
            echo "../view/user.php";
        }
    } else {
        echo "Usuario o contraseña incorrectos. Vuelve a intentarlo.";
	
        
    }
} else {
    
    echo "Error: La solicitud no es POST";
}

cerrar_conexion($con);
?>