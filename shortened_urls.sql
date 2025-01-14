PGDMP          *                |            shortened_urls    15.4    15.4                0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false                       0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            	           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            
           1262    16544    shortened_urls    DATABASE     �   CREATE DATABASE shortened_urls WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_South Africa.1252';
    DROP DATABASE shortened_urls;
                postgres    false            �            1259    16555    url_list    TABLE     �   CREATE TABLE public.url_list (
    url_card_id integer NOT NULL,
    title character varying(100) NOT NULL,
    url text NOT NULL,
    short_url character varying(50),
    user_id integer
);
    DROP TABLE public.url_list;
       public         heap    postgres    false            �            1259    16554    url_list_id_seq    SEQUENCE     �   CREATE SEQUENCE public.url_list_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.url_list_id_seq;
       public          postgres    false    217                       0    0    url_list_id_seq    SEQUENCE OWNED BY     L   ALTER SEQUENCE public.url_list_id_seq OWNED BY public.url_list.url_card_id;
          public          postgres    false    216            �            1259    16546    users    TABLE     �   CREATE TABLE public.users (
    id integer NOT NULL,
    email character varying(100) NOT NULL,
    password character varying(100),
    firstname character varying(50),
    lastname character varying(50)
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    16545    users_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public          postgres    false    215                       0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public          postgres    false    214            k           2604    16558    url_list url_card_id    DEFAULT     s   ALTER TABLE ONLY public.url_list ALTER COLUMN url_card_id SET DEFAULT nextval('public.url_list_id_seq'::regclass);
 C   ALTER TABLE public.url_list ALTER COLUMN url_card_id DROP DEFAULT;
       public          postgres    false    217    216    217            j           2604    16549    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    214    215    215                      0    16555    url_list 
   TABLE DATA           O   COPY public.url_list (url_card_id, title, url, short_url, user_id) FROM stdin;
    public          postgres    false    217   0                 0    16546    users 
   TABLE DATA           I   COPY public.users (id, email, password, firstname, lastname) FROM stdin;
    public          postgres    false    215   M                  0    0    url_list_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.url_list_id_seq', 48, true);
          public          postgres    false    216                       0    0    users_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.users_id_seq', 25, true);
          public          postgres    false    214            q           2606    16562    url_list url_list_pkey 
   CONSTRAINT     ]   ALTER TABLE ONLY public.url_list
    ADD CONSTRAINT url_list_pkey PRIMARY KEY (url_card_id);
 @   ALTER TABLE ONLY public.url_list DROP CONSTRAINT url_list_pkey;
       public            postgres    false    217            m           2606    16553    users users_email_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_key;
       public            postgres    false    215            o           2606    16551    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    215            r           2606    16563    url_list url_list_url_id_fkey    FK CONSTRAINT     |   ALTER TABLE ONLY public.url_list
    ADD CONSTRAINT url_list_url_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);
 G   ALTER TABLE ONLY public.url_list DROP CONSTRAINT url_list_url_id_fkey;
       public          postgres    false    217    3183    215                  x������ � �            x������ � �     