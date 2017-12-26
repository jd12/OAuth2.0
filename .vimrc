execute pathogen#infect()
syntax on
filetype plugin indent on
let b:quickrun_config = {'outputter/buffer/into': 1}
let g:quickrun_config = {
      \'*': {
      \'outputter/buffer/split': ':20split'},}
autocmd BufReadPost fugitive://* set bufhidden=delete
set statusline=%<%f\ %h%m%r%{fugitive#statusline()}%=%-14.(%l,%c%V%)\ %P
vnoremap <silent> # :s/^/#/<cr>:noh<cr>
vnoremap <silent> -# :s/^#//<cr>:noh<cr>
