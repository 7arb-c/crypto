def keccak_f(state):

    """

    Implements the Keccak-f permutation function.

    

    Arguments:

    state (list of list of int): A 5x5 matrix where each element is a 64-bit integer.

    

    Returns:

    list of list of int: The transformed state matrix after applying the permutation.

    """

    def theta(state):

        """ Theta step in the Keccak-f permutation. """

        C = [0] * 5

        D = [0] * 5

        for x in range(5):

            C[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]

        

        for x in range(5):

            D[x] = C[(x-1) % 5] ^ rotate_left(C[(x+1) % 5], 1)

        

        for x in range(5):

            for y in range(5):

                state[x][y] ^= D[x]



    def rho_and_pi(state):

        """ Rho and Pi steps in the Keccak-f permutation. """

        new_state = [[0] * 5 for _ in range(5)]

        for x in range(5):

            for y in range(5):

                new_state[y][(2*x + 3*y) % 5] = rotate_left(state[x][y], (x+1)*(y+1) % 64)

        return new_state



    def chi(state):

        """ Chi step in the Keccak-f permutation. """

        new_state = [[0] * 5 for _ in range(5)]

        for x in range(5):

            for y in range(5):

                new_state[x][y] = state[x][y] ^ ((~state[(x+1) % 5][y]) & state[(x+2) % 5][y])

        return new_state



    def iota(state, round_idx):

        """ Iota step in the Keccak-f permutation. """

        RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 

              0x8000000080008000, 0x000000000000808B, 0x0000000080000001,

              0x8000000080008081, 0x8000000000008009, 0x000000000000008A,

              0x0000000000000088, 0x0000000080008009, 0x000000008000000A,

              0x000000008000808B, 0x800000000000008B, 0x8000000000008089,

              0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 

              0x000000000000800A, 0x800000008000000A, 0x8000000080008081,

              0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

        state[0][0] ^= RC[round_idx]



    num_rounds = 24

    for round_idx in range(num_rounds):

        theta(state)

        state = rho_and_pi(state)

        state = chi(state)

        iota(state, round_idx)



    return state



# Helper function for rotating bits left.

def rotate_left(value, amount):

    return ((value << amount) | (value >> (64 - amount))) & 0xFFFFFFFFFFFFFFFF



# Example of initializing the state matrix and running the function

# (Commenting out to prevent execution here; this is just for demonstration)

# initial_state = [[0] * 5 for _ in range(5)]

# result_state = keccak_f(initial_state)

# print(result_state)
