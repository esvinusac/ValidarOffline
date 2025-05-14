from flask import Flask, render_template_string, request
from Crypto.Cipher import DES3
from Crypto.Hash import MD5
from base64 import b64encode
import os

# Lee la clave desde la variable de entorno
CLAVE = os.environ.get("CLAVE_OFFLINE")
if not CLAVE:
    raise Exception(
        "La variable de entorno CLAVE_OFFLINE no está definida. Debes configurarla en los Secrets de Replit."
    )

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Generador de Código Offline</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background: #f4f4f4; 
            margin: 0;
            padding: 0;
        }
        .container { 
            max-width: 400px; 
            margin: 60px auto; 
            background: #fff; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 8px #ccc; 
        }
        h2 { 
            text-align: center; 
            color: #333; 
        }
        label { 
            display: block; 
            margin-top: 15px; 
        }
        input[type="text"] { 
            width: 100%; 
            padding: 8px; 
            margin-top: 5px; 
            border-radius: 4px; 
            border: 1px solid #bbb; 
            box-sizing: border-box;
            font-size: 16px;
        }
        button { 
            margin-top: 20px; 
            width: 100%; 
            padding: 10px; 
            background: #4CAF50; 
            color: #fff; 
            border: none; 
            border-radius: 4px; 
            font-size: 16px; 
            cursor: pointer;
        }
        .result { 
            margin-top: 20px; 
            padding: 10px; 
            background: #e8f5e9; 
            border: 1px solid #4CAF50; 
            border-radius: 4px; 
            color: #2e7d32; 
            text-align: center; 
            font-size: 18px; 
            word-break: break-all;
        }
        @media (max-width: 500px) {
            .container {
                margin: 20px 5px;
                padding: 15px;
                max-width: 98vw;
            }
            h2 {
                font-size: 20px;
            }
            .result {
                font-size: 16px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Generador de Código Offline</h2>
        <form method="post">
            <label for="num1">Primer valor:</label>
            <input type="text" id="num1" name="num1" required>

            <label for="num2">Segundo valor:</label>
            <input type="text" id="num2" name="num2" required>

            <button type="submit">Generar código</button>
        </form>
        {% if codigo %}
            <div class="result">
                <strong>Código offline generado:</strong><br>
                {{ codigo }}
            </div>
            {% if descripcion %}
                <div class="result" style="background:#fffbe6; color:#8a6d3b; border:1px solid #ffe58f; margin-top:10px;">
                    <strong>Descripción:</strong><br>
                    {{ descripcion }}
                </div>
            {% endif %}
        {% endif %}
    </div>
</body>
</html>
"""


def pkcs7_pad(text, block_size=8):
    pad_len = block_size - (len(text) % block_size)
    return text + chr(pad_len) * pad_len


def cifrar(texto, clave):
    # MD5 hash de la clave
    key = MD5.new(clave.encode('utf-8')).digest()
    key = key + key[:8]  # 24 bytes para TripleDES
    cipher = DES3.new(key, DES3.MODE_ECB)
    texto_padded = pkcs7_pad(texto)
    encrypted = cipher.encrypt(texto_padded.encode('utf-8'))
    return b64encode(encrypted).decode('utf-8')


def describir_codigo(codigo):
    descripciones = []
    for c in codigo:
        if c.isdigit():
            descripciones.append(f"número {c}")
        elif c.isupper():
            descripciones.append(f"letra {c} (mayúscula)")
        elif c.islower():
            descripciones.append(f"letra {c} (minúscula)")
        else:
            descripciones.append(f"símbolo {c}")
    return ', '.join(descripciones)


@app.route("/", methods=["GET", "POST"])
def index():
    codigo = None
    descripcion = None
    if request.method == "POST":
        num1 = request.form.get("num1", "").strip()
        num2 = request.form.get("num2", "").strip()
        if num1 and num2:
            cifrado = cifrar(num1 + num2, CLAVE)
            codigo = cifrado[10:15]
            descripcion = describir_codigo(codigo)
        else:
            codigo = "Entradas inválidas"
    return render_template_string(HTML, codigo=codigo, descripcion=descripcion)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=81)
