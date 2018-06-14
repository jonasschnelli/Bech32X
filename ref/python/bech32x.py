# Copyright (c) 2017 Pieter Wuille
# Copyright (c) 2018 Bitcoin Core Developers
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Reference implementation for Bech32X."""


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32x_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x48ad7da5f5dffe2565cb2f7406b4a2bcbc, 0x55af243bb2f7943c3d4da6d046345795d, 0xa91cc8534da778785f9247a01ceda669f, 0x11a7b84839246b2e49b0c8d1039da6ddbb, 0x234e589060c8d655d131058707391d2f53]
    chk = 1
    for value in values:
        top = chk >> 130
        chk = (chk ^ top << 130) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32x_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32x_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return bech32x_polymod(bech32x_hrp_expand(hrp) + data) == 1


def bech32x_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32x_hrp_expand(hrp) + data
    polymod = bech32x_polymod(values + [0] * 27) ^ 1
    return [polymod >> (5 * (26 - i)) & 31 for i in range(27)]


def bech32x_encode(hrp, data):
    """Compute a Bech32X string given HRP and data values."""
    combined = data + bech32x_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


def bech32x_decode(bech):
    """Validate a Bech32X string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 27 > len(bech) or len(bech) > 1023:
        return (None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    if not bech32x_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-27])


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def decode(hrp, addr):
    """Decode a segwit address."""
    hrpgot, data = bech32x_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = convertbits(data, 5, 8, False)
    return decoded


def encode(hrp, data):
    """Encode Bech32X data ."""
    ret = bech32x_encode(hrp, convertbits(data, 8, 5))
    if decode(hrp, ret) == (None, None):
        return None
    return ret

# Error correction part follows

EXP = [1, 69, 229, 290, 58, 183, 166, 89, 838, 737, 199, 802, 203, 59, 242, 67, 379, 892, 598, 97, 891, 909, 730, 53, 865, 432, 839, 676, 34, 512, 241, 140, 84, 26, 573, 413, 657, 835, 944, 950, 552, 118, 538, 716, 273, 709, 857, 397, 555, 185, 821, 426, 378, 825, 691, 323, 833, 826, 636, 108, 39, 849, 896, 390, 233, 571, 3, 207, 303, 870, 107, 508, 490, 206, 362, 899, 329, 454, 349, 104, 307, 197, 936, 257, 639, 163, 264, 55, 1003, 122, 259, 757, 361, 844, 102, 672, 310, 404, 217, 11, 706, 642, 822, 357, 85, 95, 728, 191, 683, 1012, 790, 1007, 366, 663, 733, 494, 474, 766, 939, 462, 848, 965, 355, 459, 513, 180, 105, 374, 32, 650, 315, 712, 5, 337, 881, 266, 189, 545, 574, 338, 958, 37, 987, 586, 962, 184, 880, 335, 88, 771, 516, 485, 792, 124, 157, 171, 773, 922, 955, 372, 170, 832, 895, 665, 334, 29, 998, 806, 479, 943, 218, 196, 1005, 484, 861, 153, 447, 145, 946, 828, 994, 562, 587, 903, 93, 594, 373, 239, 933, 605, 675, 505, 187, 959, 96, 830, 872, 1016, 15, 982, 278, 798, 482, 707, 711, 979, 71, 111, 232, 638, 230, 493, 277, 977, 205, 421, 684, 559, 429, 161, 386, 509, 431, 43, 72, 953, 510, 352, 260, 814, 978, 2, 138, 458, 580, 81, 331, 332, 151, 556, 354, 398, 740, 406, 83, 449, 134, 723, 637, 41, 194, 627, 954, 305, 79, 610, 837, 558, 488, 68, 160, 455, 280, 141, 17, 255, 799, 423, 550, 997, 1001, 240, 201, 177, 312, 519, 298, 567, 794, 246, 343, 751, 852, 721, 759, 483, 646, 546, 753, 125, 216, 78, 551, 928, 780, 466, 243, 6, 414, 606, 620, 214, 989, 980, 412, 724, 934, 658, 908, 671, 208, 579, 394, 1008, 514, 123, 326, 528, 75, 886, 209, 518, 367, 722, 568, 204, 480, 585, 781, 407, 22, 292, 420, 745, 714, 143, 155, 309, 347, 502, 877, 681, 894, 732, 427, 319, 988, 913, 377, 1014, 924, 549, 810, 710, 918, 162, 333, 210, 713, 64, 436, 595, 304, 10, 647, 615, 532, 351, 226, 249, 641, 1017, 74, 819, 52, 804, 341, 613, 670, 149, 678, 168, 970, 693, 221, 287, 342, 682, 945, 1011, 717, 340, 544, 635, 439, 668, 31, 876, 748, 923, 1022, 401, 392, 890, 968, 575, 279, 859, 263, 993, 765, 868, 225, 54, 942, 159, 33, 719, 478, 1002, 63, 486, 983, 339, 1019, 192, 761, 624, 885, 30, 809, 521, 697, 964, 294, 302, 803, 142, 222, 464, 121, 460, 986, 527, 807, 410, 842, 504, 254, 858, 322, 772, 991, 862, 86, 144, 1015, 985, 704, 520, 764, 801, 4, 276, 916, 40, 135, 662, 664, 267, 248, 708, 796, 360, 777, 131, 898, 268, 291, 127, 82, 388, 99, 1009, 583, 158, 100, 554, 252, 976, 136, 320, 910, 533, 282, 7, 475, 699, 846, 236, 874, 882, 453, 402, 327, 597, 174, 596, 235, 689, 457, 651, 382, 557, 295, 363, 966, 428, 228, 359, 223, 405, 156, 238, 992, 696, 897, 451, 12, 793, 57, 120, 393, 831, 813, 797, 301, 1004, 417, 952, 443, 389, 38, 788, 869, 164, 211, 652, 165, 150, 617, 391, 172, 734, 289, 245, 408, 960, 50, 698, 779, 9, 584, 840, 370, 308, 286, 275, 591, 659, 969, 634, 498, 633, 317, 854, 603, 829, 935, 727, 873, 957, 234, 756, 300, 937, 324, 666, 385, 306, 128, 845, 35, 581, 20, 430, 110, 173, 667, 452, 471, 418, 887, 148, 739, 77, 744, 655, 106, 441, 271, 492, 336, 820, 495, 415, 539, 649, 500, 999, 867, 314, 653, 224, 115, 843, 445, 27, 632, 376, 947, 889, 775, 784, 625, 816, 251, 523, 563, 526, 866, 383, 616, 450, 73, 1020, 283, 66, 318, 921, 884, 91, 972, 811, 643, 883, 384, 375, 101, 623, 25, 754, 178, 503, 808, 588, 604, 742, 284, 409, 901, 215, 920, 817, 190, 750, 785, 564, 981, 473, 561, 644, 680, 827, 569, 137, 261, 875, 823, 288, 176, 381, 738, 8, 525, 941, 80, 270, 425, 437, 534, 469, 296, 701, 720, 690, 262, 932, 536, 582, 219, 129, 776, 198, 871, 46, 281, 200, 244, 477, 805, 272, 640, 956, 175, 529, 14, 915, 499, 572, 472, 628, 609, 906, 769, 654, 47, 348, 45, 470, 487, 914, 438, 729, 250, 590, 726, 812, 856, 456, 718, 411, 783, 285, 476, 864, 501, 930, 902, 24, 695, 87, 213, 786, 763, 762, 703, 602, 888, 834, 1013, 851, 778, 76, 685, 618, 328, 387, 440, 330, 265, 114, 782, 344, 313, 578, 463, 789, 800, 65, 497, 694, 18, 48, 560, 705, 589, 537, 515, 62, 419, 818, 113, 961, 119, 607, 553, 51, 767, 1006, 299, 626, 1023, 468, 365, 600, 1010, 648, 433, 770, 577, 256, 570, 70, 42, 13, 860, 220, 346, 435, 904, 907, 836, 619, 269, 358, 154, 368, 446, 212, 855, 542, 984, 645, 749, 990, 795, 179, 434, 973, 878, 614, 593, 442, 448, 195, 566, 863, 19, 117, 725, 995, 631, 686, 677, 103, 741, 467, 182, 227, 188, 612, 731, 112, 900, 146, 893, 531, 132, 601, 951, 621, 147, 824, 758, 422, 611, 768, 715, 202, 126, 23, 353, 321, 971, 752, 56, 61, 364, 541, 791, 938, 395, 949, 743, 345, 380, 679, 237, 815, 919, 231, 424, 496, 755, 247, 274, 522, 630, 747, 576, 325, 735, 356, 16, 186, 1018, 133, 540, 850, 847, 169, 911, 592, 511, 293, 481, 524, 1000, 181, 44, 403, 258, 688, 396, 622, 92, 535, 400, 461, 927, 746, 517, 416, 1021, 350, 167, 28, 931, 963, 253, 917, 109, 98, 948, 674, 444, 94, 669, 90, 905, 974, 929, 841, 311, 465, 60, 297, 760, 565, 912, 316, 787, 702, 543, 925, 608, 975, 996, 940, 21, 491, 139, 399, 673, 371, 369, 507, 49, 629, 548, 879, 547, 692, 152, 506, 116, 656, 774, 853, 660, 530, 193, 700, 661, 599, 36, 926, 687, 736, 130, 967, 489]
LOG = [-1, 0, 231, 66, 462, 132, 297, 495, 693, 561, 363, 99, 528, 825, 726, 198, 924, 264, 792, 858, 594, 990, 330, 891, 759, 660, 33, 627, 957, 165, 429, 396, 128, 416, 28, 592, 1016, 141, 542, 60, 465, 249, 824, 223, 940, 738, 715, 736, 793, 998, 558, 807, 374, 23, 413, 87, 896, 530, 4, 13, 976, 897, 799, 420, 359, 789, 647, 15, 259, 1, 823, 206, 224, 644, 372, 318, 773, 605, 291, 254, 696, 235, 480, 244, 32, 104, 454, 761, 148, 7, 969, 651, 946, 184, 967, 105, 194, 19, 963, 482, 486, 658, 94, 865, 79, 126, 608, 70, 59, 962, 596, 207, 873, 802, 781, 624, 1006, 859, 41, 804, 531, 440, 89, 315, 153, 289, 890, 479, 590, 711, 1020, 475, 878, 927, 246, 466, 490, 685, 232, 992, 31, 263, 437, 335, 455, 177, 875, 882, 603, 379, 549, 238, 1004, 175, 836, 336, 522, 154, 485, 415, 260, 219, 355, 85, 545, 548, 6, 956, 381, 931, 160, 155, 552, 597, 506, 724, 690, 273, 662, 847, 125, 939, 868, 5, 145, 49, 925, 192, 870, 136, 674, 107, 425, 1012, 250, 855, 171, 81, 713, 10, 717, 272, 889, 12, 325, 214, 73, 67, 310, 320, 357, 546, 839, 762, 301, 671, 290, 98, 170, 710, 827, 384, 438, 520, 623, 412, 368, 869, 518, 2, 210, 911, 208, 64, 582, 508, 499, 908, 523, 187, 271, 30, 14, 296, 718, 555, 279, 915, 470, 369, 744, 636, 488, 960, 448, 265, 821, 83, 942, 90, 228, 686, 706, 408, 86, 780, 135, 469, 477, 834, 697, 610, 721, 44, 916, 567, 463, 212, 200, 406, 262, 716, 494, 646, 668, 753, 566, 385, 689, 554, 3, 478, 331, 935, 434, 514, 702, 977, 276, 810, 584, 536, 435, 68, 362, 253, 589, 80, 565, 337, 96, 974, 274, 784, 621, 130, 981, 574, 648, 345, 491, 893, 450, 55, 586, 921, 316, 504, 776, 76, 779, 236, 237, 356, 164, 147, 612, 133, 139, 423, 391, 376, 386, 280, 783, 905, 828, 338, 737, 78, 955, 367, 227, 892, 240, 122, 923, 103, 835, 519, 473, 92, 74, 515, 898, 814, 112, 322, 837, 996, 564, 995, 159, 186, 127, 657, 629, 348, 52, 16, 906, 691, 512, 641, 656, 588, 220, 777, 481, 541, 63, 551, 402, 532, 312, 902, 944, 47, 241, 993, 948, 401, 503, 941, 97, 521, 243, 329, 556, 669, 445, 751, 304, 35, 298, 615, 953, 538, 601, 800, 332, 215, 885, 267, 912, 698, 51, 344, 517, 218, 595, 222, 25, 818, 848, 829, 360, 699, 742, 394, 778, 609, 853, 540, 966, 626, 838, 176, 854, 245, 643, 527, 599, 502, 77, 261, 749, 510, 233, 123, 441, 949, 119, 786, 439, 975, 295, 867, 813, 701, 739, 600, 730, 679, 116, 496, 754, 719, 418, 168, 326, 936, 202, 285, 173, 151, 421, 740, 258, 1022, 72, 991, 611, 211, 115, 614, 913, 790, 572, 728, 618, 756, 339, 663, 447, 191, 1005, 997, 71, 221, 226, 934, 29, 124, 314, 798, 150, 952, 321, 275, 459, 431, 917, 637, 937, 694, 639, 443, 317, 725, 1011, 877, 366, 493, 700, 947, 708, 797, 42, 616, 928, 899, 841, 984, 392, 137, 287, 1002, 1000, 351, 268, 292, 40, 806, 487, 48, 239, 513, 257, 217, 794, 680, 181, 638, 677, 979, 856, 277, 324, 684, 822, 65, 729, 34, 138, 405, 920, 820, 785, 311, 234, 593, 709, 484, 562, 327, 143, 182, 665, 796, 745, 568, 933, 852, 185, 361, 507, 505, 18, 1015, 815, 879, 767, 576, 666, 189, 299, 805, 986, 732, 255, 886, 871, 377, 851, 365, 642, 550, 775, 833, 300, 881, 945, 659, 427, 634, 811, 251, 731, 999, 918, 862, 628, 573, 571, 393, 58, 248, 209, 84, 722, 370, 101, 654, 681, 843, 286, 364, 817, 617, 129, 511, 547, 622, 735, 607, 1007, 36, 307, 569, 1010, 1014, 467, 113, 468, 163, 587, 598, 395, 968, 378, 309, 95, 994, 965, 190, 27, 864, 380, 907, 682, 341, 387, 108, 216, 774, 863, 1018, 943, 509, 705, 54, 1003, 383, 791, 760, 525, 432, 559, 497, 1013, 703, 983, 766, 458, 795, 100, 203, 471, 45, 353, 204, 131, 358, 334, 888, 43, 390, 750, 417, 704, 283, 323, 247, 305, 860, 746, 579, 106, 743, 22, 872, 343, 114, 553, 922, 1019, 9, 692, 604, 242, 866, 667, 904, 606, 333, 951, 919, 398, 844, 675, 281, 895, 288, 661, 914, 583, 91, 884, 284, 978, 426, 765, 764, 460, 410, 117, 808, 887, 734, 819, 149, 451, 156, 1008, 632, 712, 474, 772, 560, 294, 328, 782, 752, 633, 676, 763, 982, 543, 787, 110, 900, 152, 529, 278, 846, 472, 535, 201, 266, 788, 461, 11, 436, 375, 720, 167, 444, 664, 430, 352, 653, 747, 534, 229, 909, 635, 673, 801, 373, 613, 50, 102, 688, 883, 53, 57, 683, 179, 577, 195, 533, 161, 56, 769, 37, 832, 256, 8, 26, 563, 973, 446, 625, 93, 591, 498, 930, 120, 61, 929, 771, 282, 1009, 575, 840, 748, 46, 449, 407, 826, 174, 453, 857, 755, 24, 640, 620, 411, 544, 69, 714, 196, 580, 500, 687, 397, 340, 850, 1001, 146, 134, 501, 655, 650, 428, 319, 602, 768, 631, 403, 20, 17, 876, 342, 162, 62, 526, 476, 75, 874, 670, 758, 183, 830, 970, 733, 831, 308, 21, 492, 932, 980, 347, 741, 727, 464, 961, 354, 910, 672, 649, 157, 399, 350, 985, 1017, 950, 293, 972, 757, 958, 707, 188, 306, 578, 82, 585, 901, 118, 989, 695, 414, 169, 38, 388, 178, 630, 964, 903, 39, 880, 539, 225, 252, 158, 723, 581, 140, 193, 557, 803, 144, 959, 433, 121, 516, 1021, 404, 570, 382, 894, 652, 849, 971, 987, 489, 213, 230, 205, 303, 678, 199, 422, 842, 457, 442, 142, 346, 302, 845, 452, 524, 409, 180, 861, 988, 269, 166, 619, 938, 270, 419, 88, 537, 172, 809, 111, 313, 483, 816, 389, 109, 770, 349, 456, 197, 371, 926, 424, 645, 954, 400, 812]

def shift(a, e):
    if a == 0:
        return 0
    return EXP[(LOG[a] + e) % 1023]

def polymul(a, b):
    ret = [0] * (len(a) + len(b) - 1)
    for x in range(len(a)):
        if a[x] != 0:
            l = LOG[a[x]]
            for y in range(len(b)):
                ret[x + y] ^= shift(b[y], l)
    return ret

def polyeval(p, l):
    ret = 0
    for v in reversed(p):
        ret = shift(ret, l) ^ v
    return ret

def bech32x_solver(s, siz, err):
    m = [[s[i + j] for i in range(err + 1)] for j in range(err)]
    for rc in range(err):
        nz = ([r for r in range(rc, err) if m[r][rc] != 0] + [None])[0]
        if nz is None:
            return None
        m[nz], m[rc] = m[rc], m[nz]
        l = LOG[m[rc][rc]]
        m[rc] = [shift(x, -l) for x in m[rc]]
        for r in range(err):
            if r != rc and m[r][rc] != 0:
                m[r] = [m[r][c] ^ shift(m[rc][c], LOG[m[r][rc]]) for c in range(err + 1)]
    ret = []
    lam = [1] + [m[-(i+1)][err] for i in range(err)]
    lamd = [0 if i & 1 else m[-(1+i)][err] for i in range(err)]
    om = polymul(s, lam)[0:13]
    for p in range(siz):
        if polyeval(lam, -p) == 0:
            e = shift(polyeval(om, -p), -(19 * p + LOG[polyeval(lamd, -p)]))
            ret.append((p, e))
    return ret

def base32x_correct(expected_hrp, bech):
    """Validate and correct a Bech32X string, and determine HRP and data."""
    """Returns hrp, decoded-data, re-encoded-bech32x-string, error-positions"""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None, None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 27 > len(bech) or len(bech) > 1023:
        return (None, None, None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None, None, None)
    hrpgot = bech[:pos]
    if expected_hrp  != '*' and hrpgot != expected_hrp:
        return (None, None, None, None)
    hrp_ext = bech32x_hrp_expand(hrpgot)
    values = hrp_ext + [CHARSET.find(c) for c in bech[pos+1:]]
    syn = [0] * 14
    for v in [(bech32x_polymod(values) ^1) >> (5 * (26 - i)) & 31 for i in range(27)]:
        for i in range(14):
            syn[i] = shift(syn[i], 20 + i) ^ v
    for i in range(7, -1, -1):
        ret = bech32x_solver(syn, len(bech[pos+1:]), i)
        if ret == None:
            continue
        if len(ret) == i:
            for (p, e) in ret:
                values[-(1+p)] ^= e
            return (hrpgot, values[len(hrp_ext):-27], ''.join([CHARSET[x] for x in values[len(hrp_ext):]]), [len(bech[pos+1:]) - 1 - p for (p, e) in ret])
        return (None, None, None, None)

# Demo code

import sys

if len(sys.argv) > 2 and sys.argv[1] == 'encode':
    data = [255] + [254] + [253] + [252] + [251] + [250] + [249] + [248] + [247]
    print(encode("tx", data))
elif len(sys.argv) == 3 and sys.argv[1] == 'decode':
    hrp, data, bech, err = base32x_correct("*", sys.argv[2])
    if data is None:
        print('Unknown error')
    else:
        if len(err) > 0:
            print('Errors found: ' + ''.join('?' if i in err else bech[i] for i in range(len(bech))))
            print('Correction:   ' + bech)
        print('HRP: ' + hrp)
        print('Decoded: ' + ''.join(str(e)+" " for e in convertbits(data, 5, 8, False)))
else:
    print('Usage wrong')
