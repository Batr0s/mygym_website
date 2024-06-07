
function send_email() {
  const email = document.getElementById('email').value;
  const expresionMail = /^\w+([.-_+]?\w+)*@\w+([.-]?\w+)*(\.\w{2,10})+$/;
  if (!expresionMail.test(email)) {
    alert("Introduce una dirección de correo válida");
    return false;
  } else {
    const action = "send_email";
    const datos = {
      email,
      action
    };

    fetch('../controller/forgot_password.php', {
      method: 'POST',
      headers: {
        'Content-Type':'application/json'
      },
      body: JSON.stringify(datos)
    })
    .then(response => response.json())
    .then(data => {
      if (data.result === "1") {
        alert("Email enviado");
      } else if (data.result === "0") {
        alert("Error en el envío: " + data.message);
      }
    })
    .catch(error => {
      console.error('Error en la solicitud: ' + error);
      alert("Error en la solicitud. Inténtalo nuevamente.");
    });
  }
}
  
function change_password () {
  const password = document.getElementById("password").value;
  const confirmarPassword = document.getElementById("confirmarPassword").value;

  const expPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
  const hasMinuscula = /[a-z]/;
  const hasMayuscula = /[A-Z]/;
  const hasDigito = /[0-9]/;
  const hasSimbolo = /[@$!%*#?&]/;
  const minLongitud = 8;

  // Validación contraseña
  if (!password.match(expPassword)) {
    if (!hasMinuscula.test(password)) {
      alert('La contraseña no tiene letra minúscula.');
    } else if (!hasMayuscula.test(password)) {
      alert('La contraseña no tiene letra mayúscula.');
    } else if (!hasDigito.test(password)) {
      alert('La contraseña no tiene valor numérico.');
    } else if (!hasSimbolo.test(password)) {
      alert('La contraseña no tiene un símbolo @$!%*#?&.');
    } else if (password.length < minLongitud) {
      alert('La contraseña debe tener al menos 8 caracteres.');
    }
    return false;
  }

  // Validación contraseña sean iguales.
  if (password !== confirmarPassword) {
    alert('La contraseña y la confirmación de contraseña no coinciden.');
    return false;
  }

// Obtener la URL actual
const url = window.location.href;
// Buscar el índice del signo de igual "=" para encontrar el inicio del valor del parámetro "token"
const tokenIndex = url.indexOf("=");
// Obtener el valor del parámetro "token" a partir del índice encontrado
const token = url.slice(tokenIndex + 1);
  console.log("token ", token);

  const action = "change_password";
  const datos = {
    password,
    confirmarPassword,
    action,
    token
  };

  fetch('../controller/forgot_password.php', {
    method: 'POST',
    headers: {
      'Content-Type':'application/json'
    },
    body: JSON.stringify(datos)
  })
  .then(response => response.json())
  .then(data => {
    if (data.result === "1") {
      alert("Contraseña cambiada");
      window.location.href = "login.html";
    } else if (data.result === "0") {
      alert("Error: " + data.message);
    }
  })
  .catch(error => {
    console.error('Error en la solicitud: ' + error);
    alert("Error en la solicitud. Inténtalo nuevamente.");
  });
}
