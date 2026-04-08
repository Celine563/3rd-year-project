from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    url = ""
    status = ""
    protocol = ""
    suspicious_patterns = ""
    length_score = ""
    domain_name = ""
    registrar = ""
    owner = ""
    creation_date = ""
    expiration_date = ""
    domain_age = ""
    forms = ""
    scripts = ""
    headers = ""

    if request.method == "POST":
        url = request.form.get("url")
        status = "Safe"
        protocol = "HTTPS"
        suspicious_patterns = "None detected"
        length_score = "Normal"
        domain_age = "5 years"
        registrar = "Google"
        owner = "John Doe"
        creation_date = "2018-01-01"
        expiration_date = "2023-01-01"
        forms = "2"
        scripts = "5 external scripts"
        headers = "Security headers present"

    return render_template(
        "index.html",
        url=url,
        status=status,
        protocol=protocol,
        suspicious_patterns=suspicious_patterns,
        length_score=length_score,
        domain_name=domain_name,
        registrar=registrar,
        owner=owner,
        creation_date=creation_date,
        expiration_date=expiration_date,
        domain_age=domain_age,
        forms=forms,
        scripts=scripts,
        headers=headers
    )

if __name__ == "__main__":
    app.run(debug=True)
