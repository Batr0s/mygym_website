let hideText_btn1 = document.getElementById('hideText_btn1');
let hideText1 = document.getElementById('hideText1');

hideText_btn1.addEventListener('click', toggleText1);

function toggleText1() {
	hideText1.classList.toggle('show');

	if (hideText1.classList.contains('show')) {
		hideText_btn1.innerHTML = '-';
	}
	else {
		hideText_btn1.innerHTML = '+';
	}
}


let hideText_btn2 = document.getElementById('hideText_btn2');
let hideText2 = document.getElementById('hideText2');

hideText_btn2.addEventListener('click', toggleText2);

function toggleText2() {
	hideText2.classList.toggle('show');
	
	if (hideText2.classList.contains('show')) {
		hideText_btn2.innerHTML = '-';
	}
	else {
		hideText_btn2.innerHTML = '+';
	}
}


let hideText_btn3 = document.getElementById('hideText_btn3');
let hideText3 = document.getElementById('hideText3');

hideText_btn3.addEventListener('click', toggleText3);

function toggleText3() {
	hideText3.classList.toggle('show');

	if (hideText3.classList.contains('show')) {
		hideText_btn3.innerHTML = '-';
	}
	else {
		hideText_btn3.innerHTML = '+';
	}
}


let hideText_btn4 = document.getElementById('hideText_btn4');
let hideText4 = document.getElementById('hideText4');

hideText_btn4.addEventListener('click', toggleText4);

function toggleText4() {
	hideText4.classList.toggle('show');

	if (hideText4.classList.contains('show')) {
		hideText_btn4.innerHTML = '-';
	}
	else {
		hideText_btn4.innerHTML = '+';
	}
}


