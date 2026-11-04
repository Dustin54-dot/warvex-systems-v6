
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#09090c">
<title>WARVEX SYSTEMS V5</title>

<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#09090c;color:white;font-family:Arial,sans-serif;min-height:100vh}
header{padding:22px 18px;border-bottom:1px solid #302027;display:flex;justify-content:space-between;align-items:center}
.logo{font-size:21px;font-weight:bold;letter-spacing:2px}
.logo span{color:#ed263d}
.status{color:#48dc91;font-size:11px}
main{max-width:700px;margin:auto;padding:25px 17px 50px}
.welcome{margin:22px 0 25px}
.welcome h1{font-size:27px;margin-bottom:9px}
.welcome h1 span{color:#ed263d}
.welcome p{color:#999;font-size:14px}
.panel{background:#15151b;border:1px solid #30252c;border-radius:15px;padding:17px;margin-bottom:17px}
.panel h2{font-size:16px;margin-bottom:14px}
.system{display:grid;grid-template-columns:repeat(2,1fr);gap:11px}
.module{background:#1c1a20;border:1px solid #39252d;border-radius:12px;padding:17px 12px;color:white;text-align:left;cursor:pointer}
.module strong{display:block;margin-bottom:7px;color:#ff4056}
.module small{color:#aaa;font-size:11px}
.chat{min-height:150px;max-height:350px;overflow-y:auto;margin-bottom:12px}
.message{background:#222129;padding:12px;border-radius:10px;margin:9px 0;font-size:14px;line-height:1.5;overflow-wrap:anywhere}
.message.ai{border-left:3px solid #ed263d}
.message.user{border-left:3px solid #777}
.input-area{display:flex;gap:8px}
input{flex:1;min-width:0;background:#222129;border:1px solid #39343d;border-radius:9px;padding:13px;color:white;outline:none}
button{cursor:pointer}
.send{background:#d91e36;border:0;color:white;border-radius:9px;padding:0 17px;font-weight:bold}
.voice{width:100%;margin-top:10px;padding:13px;background:#25171d;border:1px solid #77303e;border-radius:9px;color:white}
footer{text-align:center;color:#777;font-size:11px;padding:20px}
</style>
</head>

<body>

<header>
<div class="logo">WARVEX <span>SYSTEMS</span></div>
<div class="status">● SYSTEM ONLINE</div>
</header>

<main>
<section class="welcome">
<h1>WELCOME TO <span>WARVEX V5</span></h1>
<p>Your personal AI assistant. Your digital world.</p>
</section>

<section class="panel">
<h2>◈ SYSTEM MODULES</h2>
<div class="system">

<button class="module" onclick="moduleInfo('CORE')">
<strong>◈ CORE</strong><small>AI & Intelligence</small>
</button>

<button class="module" onclick="moduleInfo('VOICE')">
<strong>◉ VOICE</strong><small>Voice Assistant</small>
</button>

<button class="module" onclick="moduleInfo('AGENT')">
<strong>⌘ AGENT</strong><small>Automation</small>
</button>

<button class="module" onclick="moduleInfo('LIFE')">
<strong>◇ LIFE</strong><small>Personal Organizer</small>
</button>

<button class="module" onclick="moduleInfo('HOME')">
<strong>⌂ HOME</strong><small>Smart Home</small>
</button>

<button class="module" onclick="moduleInfo('MEMORY')">
<strong>◉ MEMORY</strong><small>Personal Context</small>
</button>

</div>
</section>

<section class="panel">
<h2>◈ WARVEX AI CHAT</h2>

<div class="chat" id="chat">
<div class="message ai">
WARVEX V5 INITIALIZED.<br>
Hallo! Ich bin WARVEX. Wie kann ich dir helfen?
</div>
</div>

<div class="input-area">
<input id="userInput" placeholder="Nachricht an WARVEX..."
onkeydown="if(event.key==='Enter')sendMessage()">
<button class="send" onclick="sendMessage()">SEND</button>
</div>

<button class="voice" onclick="startVoice()">🎙 SPRACHSTEUERUNG</button>
</section>

<footer>
WARVEX SYSTEMS V5.0<br>
INDEPENDENT AI ARCHITECTURE
</footer>
</main>

<script>
function addMessage(text,type){
const chat=document.getElementById("chat");
const message=document.createElement("div");
message.className="message "+type;
message.textContent=text;
chat.appendChild(message);
chat.scrollTop=chat.scrollHeight;
}

function sendMessage(){
const input=document.getElementById("userInput");
const text=input.value.trim();
if(!text)return;

addMessage(text,"user");
input.value="";

setTimeout(()=>{
addMessage("Ich bin WARVEX V5. Mein KI-System wird gerade vorbereitet. Die echte KI-Anbindung folgt in einem späteren Entwicklungsschritt.","ai");
},500);
}

function moduleInfo(name){
addMessage("WARVEX "+name+" wurde ausgewählt. Dieses Modul wird schrittweise entwickelt.","ai");
}

function startVoice(){
const SpeechRecognition=window.SpeechRecognition||window.webkitSpeechRecognition;

if(!SpeechRecognition){
addMessage("Spracherkennung wird von diesem Browser nicht unterstützt. Bitte verwende die Texteingabe.","ai");
return;
}

const recognition=new SpeechRecognition();
recognition.lang="de-DE";
recognition.interimResults=false;

recognition.onresult=function(event){
const result=event.results[0][0].transcript;
document.getElementById("userInput").value=result;
sendMessage();
};

recognition.onerror=function(){
addMessage("Spracherkennung konnte nicht gestartet werden.","ai");
};

recognition.start();
}
</script>

</body>
</html>
