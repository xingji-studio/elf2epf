int math_seed = 7;
int *math_seed_pointer = &math_seed;

int math_add(int value) {
    return math_seed + value;
}

int math_read_pointer(void) {
    return *math_seed_pointer;
}
