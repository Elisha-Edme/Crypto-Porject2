from copy import deepcopy as deep
# global variable to initialize the top 3 schemes
answers = []
# dictionary that maps each scheme to its speed, security, and ease of implementation ranking, 
# as well as its hardness assumption, hormomorphism type, and the attacks it is weak to
schemes_info =   {
    'RSA': (5, 1, 9, 'RSA', 'Product', "PHE", ['timing', 'brute', 'quantum']), 
    'El Gamal': (5, 2, 8, 'DDH', 'Product',"PHE", ['brute']), 
    'Goldwasser-Micali': (5, 2, 7, 'Quadratic residuosity', 'XOR', 'PHE', ['timing']), 
    'Rabin': (5, 2, 6, 'Factoring', 'Product', 'PHE', ['replay']), 
    'Paillier': (4, 3, 5, 'N residuosity', 'Sum', 'PHE', ['quantum']), 
    'Gentry': (3, 7, 4, 'Ideal Lattice Problems', 'Arithmetic (+,*) Circuits', 'FHE', ['key leakage']), 
    'DGHV': (3, 4, 3, 'Approximate GCD', 'Boolean (AND/XOR) Circuits', 'FHE', ['dictionary', 'rainbow table']), 
    'BFV': (2, 6, 1, 'Ring Learning with Error', 'Arithmetic (+,*) Circuits', 'FHE', ['dictionary', 'rainbow table']), 
    'BGV': (2, 6, 1, 'Learning with Error', 'Arithmetic (+,*) Circuits', 'FHE', ['dictionary', 'rainbow table']), 
    'CKKS': (1, 5, 2, 'Learning with Error', 'Arithmetic (+,*) Circuits', 'FHE', ['key recovery', 'timing'])
    }

# dictionary that maps each scheme to how well they fit the preferences of the user
schemes_scores = {'RSA': 0, 'El Gamal': 0, 'Goldwasser-Micali': 0, 'Rabin': 0, 
                 'Paillier': 0, 'Gentry': 0, 'DGHV': 0, 'BFV': 0, 'BGV': 0, 
                 'CKKS': 0}

# hold the index of each piece of information in the schemes_info dictionary.
speedInd, secInd, impInd, hardInd, homoInd, typInd, vulsInd  = 0, 1, 2, 3, 4, 5, 6
# collects all the Partial homomorphic schemes into a list called PHE
PHE = ["RSA", 'El Gamal', 'Goldwasser-Micali', 'Rabin']

# Dictionary that maps each scheme to a paragraph description of the scheme
descriptions = {
    "DGHV":'''DGHV is a homomorphic encryption scheme that allows mathematical operations to be performed on encrypted data without decrypting it. It is based on the difficulty of solving certain computational problems in mathematics and computer science, such as the discrete logarithm problem. DGHV is generally considered to be secure, although it is slower than some other homomorphic encryption schemes, such as BFV. It is relatively difficult to implement and may require specialized expertise and resources. DGHV is fully homomorphic, meaning that it allows all mathematical operations to be performed on encrypted data without decrypting it. DGHV is used to perform privacy-preserving computations on sensitive data, such as data from medical records or financial transactions. It is also used in applications that require the ability to process encrypted data without revealing the plaintext, such as data analytics and machine learning.''',
    "BFV": '''BFV is a homomorphic encryption scheme that allows mathematical operations to be performed on encrypted data without decrypting it. It is based on the hardness of factoring large composite numbers, similar to RSA. BFV is generally considered to be secure, although it is slower than some other homomorphic encryption schemes, such as CKKS. It is relatively easy to implement and is widely available in software libraries and cryptographic frameworks. BFV is fully homomorphic, meaning that it allows all mathematical operations to be performed on encrypted data without decrypting it. BFV is used to perform privacy-preserving computations on sensitive data, such as data from medical records or financial transactions. It is also used in applications that require the ability to process encrypted data without revealing the plaintext, such as data analytics and machine learning.''',
    "RSA": '''RSA is a widely-used public key encryption algorithm that is based on the mathematical fact that it is relatively easy to multiply two large prime numbers together, but it is computationally infeasible to factorize a large composite number without knowing the prime factors. Textbook RSA refers to the original, unoptimized version of the RSA algorithm, which is not used in practice due to its slow performance. RSA is generally considered to be secure, although there have been some attacks against it in recent years. RSA is relatively easy to implement and is widely available in software libraries and cryptographic frameworks. It is not homomorphic. RSA is typically used to encrypt and decrypt messages, as well as to generate and verify digital signatures. It is often used in secure communication protocols, such as SSL/TLS, to protect sensitive data, such as login credentials and financial transactions.''',
    "El Gamal": '''El Gamal is a public key encryption algorithm that is based on the difficulty of solving the discrete logarithm problem. It involves generating a public key and a private key, similar to RSA. The public key consists of a prime number and a generator element, and the private key is a randomly chosen number. El Gamal is generally considered to be secure, although it is slower than some other public key algorithms, such as RSA. It is relatively easy to implement and is widely available in software libraries and cryptographic frameworks. El Gamal is partially homomorphic, meaning that it allows certain mathematical operations to be performed on encrypted data without decrypting it, but not all operations are supported. El Gamal is used to encrypt and decrypt messages, as well as to generate and verify digital signatures. It is often used in secure communication protocols, such as SSL/TLS, to protect sensitive data.''',
    'Goldwasser-Micali':'''Goldwasser-Micali (GM) is a public key encryption algorithm that is based on the hardness of finding square roots modulo a composite number. It involves generating a public key and a private key, similar to RSA and El Gamal. The public key consists of a composite number, and the private key is a randomly chosen number. GM is generally considered to be secure, although it is slower than some other public key algorithms, such as RSA. It is relatively easy to implement and is widely available in software libraries and cryptographic frameworks. GM is not homomorphic. GM is used to encrypt and decrypt messages, as well as to generate and verify digital signatures. It is often used in secure communication protocols, such as SSL/TLS, to protect sensitive data.''',
    "Rabin":'''Rabin is a public key encryption algorithm that is similar to RSA. It is based on the mathematical fact that it is relatively easy to multiply two large prime numbers together, but it is computationally infeasible to factorize a large composite number without knowing the prime factors. Rabin involves generating a public key and a private key, and the public key consists of two large prime numbers. Rabin is generally considered to be secure, although it is slower than some other public key algorithms, such as RSA. It is relatively easy to implement and is widely available in software libraries and cryptographic frameworks. Rabin is not homomorphic. Rabin is used to encrypt and decrypt messages, as well as to generate and verify digital signatures. It is often used in secure communication protocols, such as SSL/TLS, to protect sensitive data.''',
    "Paillier":'''Paillier is a public key encryption algorithm that is based on the hardness of finding large prime factors of composite numbers. It involves generating a public key and a private key, similar to RSA, El Gamal, and Rabin. The public key consists of two large prime numbers, and the private key is a randomly chosen number. Paillier is generally considered to be secure, although it is slower than some other public key algorithms, such as RSA. It is relatively easy to implement and is widely available in software libraries and cryptographic frameworks. Paillier is fully homomorphic, meaning that it allows all mathematical operations to be performed on encrypted data without decrypting it. Paillier is used to encrypt and decrypt messages, as well as to generate and verify digital signatures. It is often used in secure communication protocols, such as SSL/TLS, to protect sensitive data. It is also used in applications that require privacy-preserving computations on sensitive data, such as data from medical records or financial transactions.''',
    "Gentry": '''Gentry is a homomorphic encryption scheme that allows mathematical operations to be performed on encrypted data without decrypting it. It is based on the hardness of solving certain computational problems in mathematics and computer science, such as the shortest vector problem in lattices. Gentry is generally considered to be secure, although it is slower than some other homomorphic encryption schemes, such as BFV. It is relatively difficult to implement and may require specialized expertise and resources. Gentry is fully homomorphic, meaning that it allows all mathematical operations to be performed on encrypted data without decrypting it. Gentry is used to perform privacy-preserving computations on sensitive data, such as data from medical records or financial transactions. It is also used in applications that require the ability to process encrypted data without revealing the plaintext, such as data analytics and machine learning.''',
    "BGV":'''BGV (Brakerski-Gentry-Vaikuntanathan) is a homomorphic encryption scheme that allows mathematical operations to be performed on encrypted data without decrypting it. It is based on the hardness of factoring large composite numbers, similar to RSA. BGV is generally considered to be secure, although it is slower than some other homomorphic encryption schemes, such as CKKS. It is relatively easy to implement and is widely available in software libraries and cryptographic frameworks. BGV is fully homomorphic, meaning that it allows all mathematical operations to be performed on encrypted data without decrypting it. BGV is used to perform privacy-preserving computations on sensitive data, such as data from medical records or financial transactions. It is also used in applications that require the ability to process encrypted data without revealing the plaintext, such as data analytics and machine learning.''',
    "CKKS": '''CKKS (Cheon-Kim-Kim-Song) is a homomorphic encryption scheme that allows mathematical operations to be performed on encrypted data without decrypting it. It is based on the hardness of factoring large composite numbers, similar to RSA. CKKS is generally considered to be secure, although it is faster than some other homomorphic encryption schemes, such as BFV. It is relatively easy to implement and is widely available in software libraries and cryptographic frameworks. CKKS is fully homomorphic, meaning that it allows all mathematical operations to be performed on encrypted data without decrypting it. CKKS is used to perform privacy-preserving computations on sensitive data, such as data from medical records or financial transactions. It is also used in applications that require the ability to process encrypted data without revealing the plaintext, such as data analytics and machine learning.'''
}

# dictionary that maps a scheme to 3 links to display in the results page
links = {
    'RSA': ["https://www.encryptionconsulting.com/education-center/what-is-rsa/", "https://history-computer.com/rsa-encryption/", "https://www.infoworld.com/article/3650488/understand-the-rsa-encryption-algorithm.html"],
    'BGV': ['https://eprint.iacr.org/2022/706.pdf', 'https://web.wpi.edu/Pubs/ETD/Available/etd-042716-165941/unrestricted/jdong.pdf', 'https://www.ic.unicamp.br/~reltech/PFG/2018/PFG-18-28.pdf'],
    'El Gamal': ["https://www.geeksforgeeks.org/elgamal-encryption-algorithm/", "https://homepages.math.uic.edu/~leon/mcs425-s08/handouts/el-gamal.pdf", "https://cryptography.fandom.com/wiki/ElGamal_encryption"],
    'Goldwasser-Micali': ["https://www.johndcook.com/blog/2019/03/06/goldwasser-micali/", "https://www.youtube.com/watch?v=GjQahRvC5po", "http://www.cs.tufts.edu/comp/165/papers/Goldwasser-Bellare-notes-cryptography.pdf"],
    'Rabin': ['https://www.geeksforgeeks.org/rabin-cryptosystem-with-implementation/', 'https://www.diva-portal.org/smash/get/diva2:1581080/FULLTEXT01.pdf', 'https://iopscience.iop.org/article/10.1088/1742-6596/1235/1/012084/pdf'],
    'Paillier': ["https://blog.openmined.org/the-paillier-cryptosystem/", "https://www.cae.tntech.edu/~mmahmoud/teaching_files/grad/ECE7970/S16/slides/Homomorphic_basics.pdf", 'https://uomustansiriyah.edu.iq/media/lectures/5/5_2021_06_05!07_15_10_PM.pdf'],
    'Gentry': ['https://www.cs.cmu.edu/~odonnell/hits09/gentry-homomorphic-encryption.pdf', 'https://www.youtube.com/watch?v=487AjvFW1lk', 'https://ceur-ws.org/Vol-2654/paper5.pdf'],
    'DGHV': ['https://eprint.iacr.org/2014/068.pdf', 'https://www.gta.ufrj.br/ftp/gta/TechReports/PAD12.pdf', 'https://asecuritysite.com/encryption/hom_public'],
    'BFV': ['https://eprint.iacr.org/2022/706.pdf', 'https://web.wpi.edu/Pubs/ETD/Available/etd-042716-165941/unrestricted/jdong.pdf', 'https://www.ic.unicamp.br/~reltech/PFG/2018/PFG-18-28.pdf'],
    'CKKS': ['https://blog.openmined.org/ckks-explained-part-3-encryption-and-decryption/#:~:text=CKKS%20is%20a%20public%20key,and%20must%20be%20kept%20secret.', 'https://www.inferati.com/blog/fhe-schemes-ckks', 'https://palisade-crypto.org/security-of-ckks/']
}

def p1(ans):
    global schemes_scores, speedInd, secInd, impInd, hardInd, homoInd, typInd, vulsInd, schemes_info
    for scheme in schemes_scores:
        # Adds the rank of the speed to the scheme score
        schemes_scores[scheme] += schemes_info[scheme][speedInd]* int(ans['Speed'])
        # Adds the rank of the ease of Implementation to the scheme score
        schemes_scores[scheme] += schemes_info[scheme][impInd] * int(ans['Implementation'])
        # Adds the rank of the security to the scheme score
        schemes_scores[scheme] += schemes_info[scheme][secInd] * int(ans['Security'])
        # Adds the weighting of the type of homomorphic encryption if the scheme has the selected
        # encryption type
        schemes_scores[scheme] += (schemes_info[scheme][typInd] == ans['ques2']) * 120
        if ans['ques1'] == schemes_info[scheme][hardInd]:
            schemes_scores[scheme] += 5000

def p2(ans):
    global schemes_scores, speedInd, secInd, impInd, hardInd, homoInd, typInd, vulsInd, schemes_info
    for scheme in schemes_scores:
        # subtracts the rank of the attack from the score
        for attack in schemes_info[scheme][vulsInd]:
            schemes_scores[scheme] -= int(ans[attack]) * 5
        # add to scheme score depending on application type
        schemes_scores[scheme] += bool(ans.get("opt1")) * (schemes_info[scheme][typInd] == "PHE") * 10
        schemes_scores[scheme] += bool(ans.get("opt2")) * (schemes_info[scheme][typInd] == "FHE" or scheme == "RSA") * 10
        schemes_scores[scheme] += bool(ans.get("opt3")) * (schemes_info[scheme][typInd] == "FHE") * 10
        schemes_scores[scheme] += bool(ans.get("opt4")) * (scheme == "RSA") * 10
        # adds the hardness to the scheme score if the hardness is 
        if schemes_info[scheme][hardInd] == ans["ques6"]:
            schemes_scores += 1000

def getTop3():
    global answers
    # makes a list [score, scheme]
    for scheme in schemes_scores:
        answers.append((schemes_scores[scheme], scheme))
    # sorts by score and adds the top 3 scored schemes to answers
    answers = [tup[1] for tup in sorted(answers, reverse=True)[0:3]]


from flask import *
app = Flask(__name__)

@app.route('/')
@app.route('/home')
def home_page():
    answers.clear()
    return render_template("home_page.html")

@app.route('/page1', methods = ['POST', 'GET'])
def page1():
    if request.method == "POST":
        # Add data to answer list
        p1(request.form)
        # redirect to next page
        return redirect(url_for("page2"))
    else:
        return render_template("page1.html")

@app.route('/page2', methods = ['POST', 'GET'])
def page2():
    if request.method == "POST":
        # Add data to answer list
        p2(request.form)
        # store the top 3 schemes in the answers list
        getTop3()
        # redirect to next page
        return redirect(url_for("results"))
    return render_template("page2.html")


@app.route('/results')
def results():
    # makes a deepcopy of the answers
    ans = deep(answers)
    # stores the description of the scheme, the place, and the scheme name into a tuple within a list
    ans = [(i, ans[i],descriptions[ans[i]]) for i in range(len(ans))]
    # passes in the neccassary results to display
    return render_template("results.html", ls=ans, link=links)

if __name__ == '__main__':
    app.run(debug=True)