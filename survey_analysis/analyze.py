import os
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.express as px
import spacy
import gensim
import gensim.corpora as corpora
from gensim.models import CoherenceModel
import pyLDAvis
import pyLDAvis.gensim_models as gensimvis
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- CONFIGURATION ---
DATA_PATH = 'data/full_survey_responses.csv'
OUTPUT_DIR = 'output'
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_and_prep_data():
    print("Loading data...")
    df = pd.read_csv(DATA_PATH)
    
    # Ensure numerical columns are correctly typed for plotting
    df['Years_Of_Experience'] = pd.to_numeric(df['Years_Of_Experience'], errors='coerce')
    
    # Standardize 'NA' strings to actual NaNs for cleaner aggregations in certain plots
    df.replace('NA', pd.NA, inplace=True)
    
    return df

def quantitative_analysis(df):
    print("Running Baseline Quantitative Analysis...")
    
    # 1. Seaborn: Regional Distribution
    plt.figure(figsize=(10, 6))
    sns.countplot(y='Region', data=df, order=df['Region'].value_counts().index, palette='viridis')
    plt.title('Regional Distribution of Developers')
    plt.xlabel('Count')
    plt.ylabel('Region')
    plt.tight_layout()
    plt.savefig(f'{OUTPUT_DIR}/01_regional_distribution.png')
    plt.close()

    # 2. Seaborn: Hashing Scheme Preferences
    plt.figure(figsize=(10, 6))
    sns.countplot(y='Preferred_Hashing_Schemes', data=df, order=df['Preferred_Hashing_Schemes'].value_counts().index, palette='magma')
    plt.title('Preferred Hashing Schemes')
    plt.xlabel('Count')
    plt.ylabel('Hashing Scheme')
    plt.tight_layout()
    plt.savefig(f'{OUTPUT_DIR}/02_preferred_hashing_schemes.png')
    plt.close()

def multivariate_analysis(df):
    print("Running Multivariate Analysis for Training Needs and Algorithm Choices...")

    # --- 1. Identifying Training Needs: OWASP Familiarity vs. Review Habits ---
    plt.figure(figsize=(8, 6))
    crosstab_training = pd.crosstab(df['Familiar_With_OWASP'], df['Regularly_Review_Knowledge'])
    sns.heatmap(crosstab_training, annot=True, cmap="YlGnBu", fmt='g')
    plt.title('Training Gap Analysis: OWASP Familiarity vs. Review Frequency')
    plt.ylabel('Familiar with OWASP')
    plt.xlabel('Regularly Reviews Security Knowledge')
    plt.tight_layout()
    plt.savefig(f'{OUTPUT_DIR}/03_training_needs_heatmap.png')
    plt.close()

    # --- 2. Practice vs Experience: Do senior devs make better choices? ---
    # Filter out NaNs for plotting
    plot_df = df.dropna(subset=['Preferred_Storage_Method', 'Years_Of_Experience', 'Familiar_With_OWASP'])
    
    plt.figure(figsize=(12, 8))
    sns.boxplot(x='Years_Of_Experience', y='Preferred_Storage_Method', hue='Familiar_With_OWASP', data=plot_df, palette='Set2')
    plt.title('Storage Method by Years of Experience & OWASP Familiarity')
    plt.xlabel('Years of Experience')
    plt.ylabel('Preferred Storage Method')
    plt.legend(title='OWASP Familiarity', loc='lower right')
    plt.tight_layout()
    plt.savefig(f'{OUTPUT_DIR}/04_experience_vs_practice_boxplot.png')
    plt.close()

    # --- 3. Interactive Sunburst: Educational Background -> Algorithm -> Reason ---
    # This traces exactly WHY certain algorithms are chosen based on the developer's background
    sunburst_df = df.dropna(subset=['Path_Into_Tech', 'Preferred_Hashing_Schemes', 'Reason_Hashing_Scheme'])
    
    fig_sun = px.sunburst(
        sunburst_df, 
        path=['Path_Into_Tech', 'Preferred_Hashing_Schemes', 'Reason_Hashing_Scheme'], 
        title="Rationale Pathway: Education -> Hashing Algorithm -> Reason",
        color='Preferred_Hashing_Schemes',
        color_discrete_sequence=px.colors.qualitative.Pastel
    )
    fig_sun.update_traces(textinfo="label+percent parent")
    fig_sun.write_html(f'{OUTPUT_DIR}/05_rationale_sunburst.html')

    # --- 4. Interactive Treemap: Review Habits -> Hashing Scheme -> Encountered Vulnerabilities ---
    # Identifies if certain algorithm choices correlate with past vulnerabilities
    tree_df = df.dropna(subset=['Regularly_Review_Knowledge', 'Preferred_Hashing_Schemes', 'Encountered_Vulnerability'])
    
    fig_tree = px.treemap(
        tree_df, 
        path=['Regularly_Review_Knowledge', 'Preferred_Hashing_Schemes', 'Encountered_Vulnerability'],
        title="Vulnerability Mapping: Review Habits & Hashing Schemes",
        color='Encountered_Vulnerability',
        color_discrete_map={'Yes': 'salmon', 'No': 'lightgreen', "I'm unsure": 'lightgrey'}
    )
    fig_tree.write_html(f'{OUTPUT_DIR}/06_vulnerability_treemap.html')
    
    print("Multivariate visualizations saved.")

def qualitative_analysis_lda(df):
    print("Running Qualitative Analysis (LDA Topic Modeling)...")
    nlp = spacy.load("en_core_web_sm", disable=['parser', 'ner'])
    
    def preprocess_text(text):
        doc = nlp(str(text))
        allowed_postags = ['NOUN', 'ADJ', 'VERB', 'ADV']
        return [token.lemma_.lower() for token in doc 
                if not token.is_stop and not token.is_punct and token.pos_ in allowed_postags]

    text_data = df.dropna(subset=['Reason_Hashing_Scheme'])['Reason_Hashing_Scheme']
    data_words = text_data.apply(preprocess_text).tolist()

    # Remove empty sublists
    data_words = [words for words in data_words if words]

    id2word = corpora.Dictionary(data_words)
    corpus = [id2word.doc2bow(text) for text in data_words]

    best_coherence = -1
    best_model = None
    best_num_topics = 2

    print("Evaluating models for optimal coherence...")
    for num_topics in range(2, 6):
        lda_model = gensim.models.LdaMulticore(corpus=corpus, id2word=id2word, num_topics=num_topics, 
                                               random_state=100, passes=10, alpha='symmetric', eta='symmetric')
        coherence_model = CoherenceModel(model=lda_model, texts=data_words, dictionary=id2word, coherence='c_v')
        coherence_score = coherence_model.get_coherence()
        
        print(f"Num Topics: {num_topics} | Coherence Score: {coherence_score:.4f}")
        
        if coherence_score > best_coherence:
            best_coherence = coherence_score
            best_model = lda_model
            best_num_topics = num_topics

    print(f"Optimal model selected with {best_num_topics} topics (Coherence: {best_coherence:.4f}).")

    vis = gensimvis.prepare(best_model, corpus, id2word)
    pyLDAvis.save_html(vis, f'{OUTPUT_DIR}/07_lda_topic_visualization.html')
    print("Interactive LDA visualization saved.")

if __name__ == "__main__":
    df = load_and_prep_data()
    quantitative_analysis(df)
    multivariate_analysis(df)
    qualitative_analysis_lda(df)
    print("Analysis complete. Check the '/output' directory.")