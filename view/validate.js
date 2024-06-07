let form = document.forms["form"];
form["nombre"].addEventListener("input", validarNombre, false);
form["email"].addEventListener("input", validarMail, false);
form["pass"].addEventListener("input", validarPassword, false);
form.addEventListener("submit", validarFormulario, false);

function validarNombre() {
  let inputNombre = form["nombre"];
  let valorNombre = inputNombre.value;
  let infoSpanNombre = document.getElementById("mensajeNombre");
  let expresionNombre = /^[A-z]{2,}$/;
  if (!expresionNombre.test(valorNombre)) {
    infoSpanNombre.innerHTML = "Introduce un nombre válido";
    return false;
  } else {
    infoSpanNombre.innerHTML = "Nombre correcto";
    return true;
  }
}

function validarMail() {
  let inputMail = form["email"];
  let valorMail = inputMail.value;
  let infoSpanMail = document.getElementById("mensajeMail");
  let expresionMail = /^\w+([.-_+]?\w+)*@\w+([.-]?\w+)*(\.\w{2,10})+$/;
  if (!expresionMail.test(valorMail)) {
    infoSpanMail.innerHTML = "Introduce una dirección de correo válido";
    return false;
  } else {
    infoSpanMail.innerHTML = "Correo correcto";
    return true;
  }
}

function validarPassword() {
  let inputContra = form["pass"];
  let valorContra = inputContra.value;
  let infoSpanContra = document.getElementById("mensajeContra");
  let expresionContra = /^[A-z]{6,}$/;
  if (!expresionContra.test(valorContra)) {
    infoSpanContra.innerHTML = "Contraseña incorrecta";
    return false;
  } else {
    infoSpanContra.innerHTML = "Contraseña correcta";
    return true;
  }
}

function validarFormulario(e) {
  e.preventDefault();
  if (validarNombre() && validarMail() && validarPassword()) {
    window.location.href = "bienvenido.html";
  }
}

function validarRegistro() {
  // Inputs del formulario
  let nombre = document.getElementById('nombre').value;
  let apellidos = document.getElementById('apellidos').value;
  let edad = document.getElementById('edad').value;
  let email = document.getElementById('email').value;
  let telefono = document.getElementById('telefono').value;
  let password = document.getElementById('password').value;
  let confirmarPassword = document.getElementById('confirmarPassword').value;

  let tarifasRegistro = document.querySelector('.tarifas-registro');
  let div_formulario = document.querySelector('.formulario_contacto');

  let response = grecaptcha.getResponse();
  if (response.length == 0) {
    alert('Verificar captcha');
    return false;
  }

  // Validación del nombre y apellidos mínimo 2 caracteres.
  if (nombre.length < 2 || apellidos.length < 2) {
    alert('Nombre y apellidos deben tener al menos dos caracteres.');
    return false;
  }

  // Validación mayor de edad.
  let fechaNacimiento = new Date(edad);
  let hoy = new Date();
  let edadCalculada = hoy.getFullYear() - fechaNacimiento.getFullYear();
  if (edadCalculada < 18) {
    alert('Debes ser mayor de edad para registrarte.');
    return false;
  }

  // Validación formato correo electrónico.
  let emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email.match(emailRegex)) {
    alert('El correo electrónico no tiene un formato válido.');
    return false;
  }

  // Validación teléfono tiene 9 números.
  let telefonoRegex = /^\d{9}$/;
  if (telefono.length > 0 && !telefono.match(telefonoRegex)) {
    alert('El número de teléfono debe tener 9 números.');
    return false;
  }

  let expPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
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

  const datos = {
    nombre,
    apellidos,
    edad,
    email,
    telefono,
    password,
    confirmarPassword,
    response
  };

  fetch('../controller/validate.php', {
    method: 'POST',
    headers: {
      'Content-Type':'application/json'
    },
    body: JSON.stringify(datos)
  })
  .then(response => response.json())
  .then(data => {
    if (data.result === "1") {
      alert("Formulario validado");
      tarifasRegistro.classList.add('show-price');
      div_formulario.classList.add('hide-formulario_contacto');
    } else if (data.result === "0") {
      alert("Error en el registro: " + data.message);
    }
  })
  .catch(error => {
    console.error('Error en la solicitud: ' + error);
    alert("Error en la solicitud. Inténtalo nuevamente.");
  });

  return false;
}

