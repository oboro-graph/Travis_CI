import gmpy2




def paillier_key_gen(p, q):
    #Generates the key to be used in the Paillier algorithm
    
    #Step 1: Compute n which is the product of p and q
    n = gmpy2.mul(p, q)
    
    #Step 2: Compute lambda---> (λ)
    lam_da = gmpy2.mul(p-1, q-1)
    
    #Step 3: Set g
    g = n + 1
    
    #Return sets of Tuples: (g, n) as the public key and (lam_da(λ), p, q) as the private key
    return((g, n), (lam_da, p, q))


def random_msg_gen():
    #This function is to generate a random msge
    
    bit_count = 128   
    #Sets bit count to 128-bit security level

    randd_state = gmpy2.random_state(42)
    #Hash(gmpy2.random_state(42)) wil generate random integer to be used as the random state
    
    msg = gmpy2.mpz_rrandomb(randd_state, bit_count)
    # Random msge using the random_state and bit count(b) security specifications.. 
    # Recall: random_state(42) must be set first before using mpz_rrandomb"""
    
    return msg


def paillier_encryption(pk, msg):

    # Unpacking the public key into g and n, 
    # and used to encrypt the msge
    g, n = pk
    
    #Step 1: Use the random msge generated from the function: random_msg_gen

    #Step 2: Generate random r
    bit_count = 128 #Sets bit count to 128-bit security level
    randd_state = gmpy2.random_state(hash(gmpy2.random_state()))
    #Used hash(gmpy2.random_state()) to generate a random integer to be used as the random state
    
    r = gmpy2.mpz_rrandomb(randd_state, bit_count)
    #Generates a random value for 'r' using the random state and bit count security specifications
        
    #Step 3: Computes CipherText
    mod_sqr = gmpy2.mpz(n)*n
    
    #Dividing the CipherText into two
    first_Share_msg = gmpy2.powmod(g, msg, mod_sqr)
    second_Share= gmpy2.powmod(r, n, mod_sqr)
    
    c = gmpy2.mul(first_Share_msg, second_Share)
    
    #Where r is the generated random 'r' and c is the encrypted msge
    return (r, c)


def paillier_decryption(secret_key, c, n):
    #Decrypts the encrypted msge to get the original msge
    
    #Step 1: Compute Secret Key
    lambda_ = secret_key[0]
    mod_sqr = gmpy2.mpz(n)*n

    #From L(x) = ((x - 1) / n) mod n
    x = gmpy2.powmod(c, lambda_, mod_sqr)
    S = gmpy2.mod((x - 1) // n, n)
    
    #Step 2: Compute decrypption_process
    lambda_inverse = gmpy2.invert(lambda_, n)
    decrypption_process = gmpy2.mod(gmpy2.mul(S, lambda_inverse), n)
    
    return decrypption_process


p = """9138420210907144229346383602111224287220211255699723373865077111530462706843524418945
    2217404518350934650625169787645878831492249234702966702870665364147218752886578786376
    7660427701070581233231729618984962904677904952297611915176997583876453145550989763054
    5814723308394740985648629502758462834385234619829483467339805651856597030613705766204
    2381108071850367597403128086501769091999204250111973206216989075174484334959172281822
    465253170809350903328437985069427319"""
    
q = """8146161860995192671423248607332368184360571181358612946908952188128657824035160921147
    0308250561781558375310490543983933780038328473513066035201591085583608631590043360965
    7858670677252072623144289579736424401668386783056580120187273937377443492092499248480
    6906199226505168652645256426009799321453205741509083711373085956008163786250422320893
    1316591467688041729971515846931082731879867661935144206080893902297595573259652166808
    407688180529379028374251689469303983"""
    
p = gmpy2.mpz(p)
q = gmpy2.mpz(q)
    
#provide values to the functions and print outputs

print(f'Prime (p) = {p}\n')
print(f'Prime (q) = {q}\n')
    
pub_key, secret_key = paillier_key_gen(p, q)
print(f'The composite modulus n = {pub_key[1]}\n')
print(f'The encryption exponent λ = {secret_key[0]}\n\n')
    
msge = random_msg_gen()
r, c = paillier_encryption(pub_key, msge)
    
print('Encryption:\n')
print(f'Random msge = {msge}\n')
print(f'The random number (r) = {r}\n')
print(f'Ciphertext = {c}\n\n')
    
decryption_process = paillier_decryption(secret_key, c, pub_key[1])
    
print('Decryption:\n')
print(f'Ciphertext = {c}\n')
print(f'Decrypted Message Enc(c) = {decryption_process}\n')

#Compare to make sure the Enc(m) anc Dec(c) are the same
        
if msge == decryption_process:
    print('Both original and decrypted messages are equal')
else:
    print('no match betwn Enc and Dec messages')