import ast
from decimal import Decimal


iter_cols = ['password', 'guesses', 'guesses_log10', 'sequence', 'calc_time', 'crack_times_seconds', 'score']
gen_cols = ['password', 'guesses', 'guesses_log10', 'calc_time', 'offline_slow_hashing_1e4_per_second','offline_fast_hashing_1e10_per_second', 'score']
seq_cols = ['password', 'pattern', 'token', 'guesses_log10']
crack_cols = [ 'offline_slow_hashing_1e4_per_second','offline_fast_hashing_1e10_per_second']

class TreatZxcvbn:
    def __init__(self, df, z_col='zxcvbn_score', crack_cols=crack_cols, iter_cols=iter_cols, gen_cols=gen_cols, seq_cols=seq_cols):
        self.iter_cols = iter_cols
        self.crack_cols = crack_cols
        self.gen_cols = gen_cols
        self.z_scores = df[z_col].to_list()
        self.passwords = df['passwords'].to_list()
        self.seq_cols = seq_cols
        self.gen_ext = {c:[] for c in self.gen_cols}
        self.seq_ext = {c:[] for c in self.seq_cols}
        

    def extract_sequence(self, pswd, seq_list):
        try:
            count = len(seq_list)
        except:
            count = 0

        if count == 0:
            for k in self.seq_ext:
                if k != 'password':
                    self.seq_ext[k].append(None)
            self.seq_ext['password'].append(pswd)

        else:
            for seq in seq_list:
                for k in self.seq_ext:
                    if k != 'password':
                        self.seq_ext[k].append(seq[k])
            
            for i in range(count):
                self.seq_ext['password'].append(pswd)


    def extract_crack_time(self, crack_time):
        for c in self.crack_cols:
            if crack_time:
                t = crack_time[c]
                self.gen_ext[c].append(t)
                # start = t.index("(") + 1 
                # self.gen_ext[c] = Decimal(ast.literal_eval(t[start:-1]))
            else:
                 self.gen_ext[c].append(None)


    def extract(self): 
        for i,result in enumerate(self.z_scores):
            if result:
                pswd = result['password']
                for k in self.iter_cols:
                    if k == 'sequence':
                        self.extract_sequence(pswd, seq_list=result[k])
                    elif k == 'crack_times_seconds':
                        self.extract_crack_time(crack_time=result[k])
                    else:
                        self.gen_ext[k].append(result[k])
            else:
                pswd = self.passwords[i]
                for k in self.iter_cols:
                    if k == 'sequence':
                        self.extract_sequence(pswd, seq_list=None)
                    elif k == 'crack_times_seconds':
                        self.extract_crack_time(crack_time=None)
                    elif k == 'password':
                        self.gen_ext[k].append(pswd)
                    else:
                        self.gen_ext[k].append(None)

    def out_put(self):
        return {'password_dict':self.gen_ext, 'sequenc_dict':self.seq_ext}