from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    url = None
    if request.method == "POST":
        url = request.form.get("url")
    
    return render_template("index.html", url=url)

if __name__ == "__main__":
    app.run(debug=True)
