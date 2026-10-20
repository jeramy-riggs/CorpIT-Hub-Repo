/* Inventory Device 360: on-demand, read-only reuse of existing person/device evidence. */
(function () {
  'use strict';
  const text=v=>v==null?'':String(v);
  const esc=v=>text(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const present=v=>v==null||v===''?'Not reported':String(v);
  const truth=v=>v===true?'Yes':v===false?'No':'Unknown';
  const recordsFor=s=>s&&['ok','partial'].includes(s.status)&&Array.isArray(s.records)?s.records:[];
  const unique=values=>[...new Set(values)];
  // Vector geometry from the existing workspace landing-icons library; no external loads.
  const manufacturerMarks={"dell":{"label":"Dell","viewBox":"0 0 512 512","paths":["M256 27.7c-63 0-120.1 25.6-161.4 66.9C53.2 135.9 27.7 193 27.7 256s25.6 120.1 66.9 161.4S193 484.3 256 484.3s120.2-25.6 161.4-66.9c41.3-41.3 66.8-98.4 66.8-161.4c0-63.1-25.5-120.2-66.8-161.4c-41.2-41.4-98.3-66.9-161.4-66.9M256 0c141.4 0 256 114.6 256 256c0 141.3-114.6 256-256 256C114.7 512 0 397.4 0 256S114.7 0 256 0M134.9 253.9c0-14.9-9.9-23.4-23.9-23.4h-8.6v46.8h8.3c13.1.1 24.2-7 24.2-23.4m152.6 16.9l-63.2 49.8l-57.8-45.5c-8.3 20-28.5 33.9-51.7 33.9H65.5V198.9h49.4c25.9 0 44.6 16.5 51.6 34l57.8-45.4l21.4 16.8l-52.9 41.7l10.2 8l52.9-41.6l21.4 16.8l-52.9 41.7l10.2 8l53-41.7V199H326v78h38.3v32.3h-76.7c-.1-.2-.1-38.5-.1-38.5m125.4 6.1h38.3v32.3h-76.7V198.9h38.4z"]},"apple":{"label":"Apple","viewBox":"0 0 512 512","paths":["M451.1 174.6c-3 2.3-55.4 31.8-55.4 97.5c0 76 66.7 102.9 68.7 103.5c-.3 1.6-10.6 36.8-35.2 72.7c-21.9 31.5-44.8 63-79.6 63s-43.8-20.2-84-20.2c-39.2 0-53.1 20.9-84.9 20.9s-54.1-29.2-79.6-65c-29.6-42.1-53.5-107.5-53.5-169.5c0-99.5 64.7-152.3 128.4-152.3c33.8 0 62.1 22.2 83.3 22.2c20.2 0 51.8-23.6 90.3-23.6c14.6 0 67 1.3 101.5 50.8m-119.8-93c15.9-18.9 27.2-45.1 27.2-71.3c0-3.6-.3-7.3-1-10.3c-25.9 1-56.7 17.3-75.3 38.8c-14.6 16.6-28.2 42.8-28.2 69.4c0 4 .7 8 1 9.3c1.6.3 4.3.7 7 .7c23.2-.1 52.4-15.6 69.3-36.6"]},"hp":{"label":"HP","viewBox":"0 0 24 24","paths":["M12.007 24h-.357l2.459-6.745h3.38c.59 0 1.236-.454 1.442-1.017l2.665-7.308c.44-1.196-.247-2.171-1.525-2.171h-4.698l-3.93 10.798l-2.225 6.127A11.995 11.995 0 0 1 0 12.007C0 6.498 3.71 1.855 8.765.44L6.47 6.759L2.65 17.255h2.542l3.256-8.916h1.91l-3.256 8.916h2.541l3.022-8.325c.44-1.195-.247-2.17-1.525-2.17H8.998l2.46-6.746C11.635 0 11.814 0 11.992 0C18.628 0 24 5.372 24 12.007C24.014 18.629 18.642 24 12.007 24m7.267-15.675h-1.91l-2.678 7.336h1.91z"]},"lenovo":{"label":"Lenovo","viewBox":"0 0 24 24","paths":["M21.044 12.288c0 .5-.343.867-.815.867c-.464 0-.827-.38-.827-.867c0-.51.343-.868.815-.868c.464 0 .827.381.827.868m-14.305-.92a.79.79 0 0 0-.651.307a1 1 0 0 0-.172.738l1.479-.614a.71.71 0 0 0-.656-.43zm6.963.052c-.472 0-.816.358-.816.868c0 .486.364.867.828.867c.472 0 .815-.368.815-.867c0-.487-.363-.868-.827-.868M24 7.997v8.006H0V7.997zM5.01 13.05H3.088V9.825H2.23v4.003h2.78zm1.137-.094l2.163-.897a1.67 1.67 0 0 0-.37-.86c-.284-.33-.704-.505-1.216-.505c-.931 0-1.633.686-1.633 1.593c0 .93.704 1.593 1.726 1.593c.572 0 1.158-.272 1.432-.589l-.535-.411c-.357.264-.56.326-.885.326c-.292 0-.52-.09-.682-.25m5.57-1.039c0-.709-.507-1.223-1.252-1.223a1.28 1.28 0 0 0-1.005.494v-.442h-.846v3.081h.846v-1.753c0-.316.245-.651.698-.651c.35 0 .712.243.712.651v1.753h.847zm3.647.37c0-.904-.725-1.593-1.65-1.593c-.933 0-1.663.7-1.663 1.593c0 .903.726 1.592 1.651 1.592c.932 0 1.662-.7 1.662-1.592m2.066 1.54l1.268-3.081h-.967l-.765 2.099l-.765-2.1h-.966l1.268 3.081zm4.449-1.54c0-.904-.725-1.593-1.65-1.593c-.932 0-1.662.7-1.662 1.593c0 .903.725 1.592 1.65 1.592c.932 0 1.662-.7 1.662-1.592"]},"microsoft":{"label":"Microsoft","viewBox":"0 0 512 512","paths":["M22.3 22.3h222.6v222.6H22.3z","M267.1 22.3h222.6v222.6H267.1z","M22.3 267.1h222.6v222.6H22.3z","M267.1 267.1h222.6v222.6H267.1z"]},"acer":{"label":"Acer","viewBox":"0 0 24 24","paths":["M23.943 9.364c-.085-.113-.17-.198-.595-.226c-.113 0-.453-.029-1.048-.029c-1.56 0-2.636.482-3.175 1.417c.142-.935-.765-1.417-2.749-1.417c-2.324 0-3.798.935-4.393 2.834c-.226.709-.226 1.276-.056 1.73h-.567c-.425.027-.992.056-1.36.056c-.85 0-1.39-.142-1.588-.425c-.17-.255-.17-.737.057-1.446c.368-1.162 1.247-1.672 2.664-1.672c.737 0 1.445.085 1.445.085c.085 0 .142-.113.142-.198l-.028-.085l-.057-.397c-.028-.255-.227-.397-.567-.453c-.311-.029-.567-.029-.907-.029h-.028c-1.842 0-3.146.624-3.854 1.814c.255-1.219-.596-1.814-2.551-1.814c-1.105 0-1.9.029-2.353.085c-.368.057-.595.199-.68.454l-.17.51c-.028.085.029.142.142.142c.085 0 .425-.057.992-.086a25 25 0 0 1 1.672-.085c1.077 0 1.559.284 1.389.822c-.029.114-.114.199-.255.227c-1.02.17-1.842.284-2.438.369c-1.7.226-2.692.736-2.947 1.587c-.369 1.162.538 1.728 2.72 1.728c1.078 0 2.013-.056 2.75-.198c.425-.085.652-.17.737-.453l.396-1.304c-.028 1.304.85 1.955 2.721 1.955c.794 0 1.559-.028 1.927-.085c.369-.056.567-.141.652-.425l.085-.396c.397.623 1.276.935 2.608.935c1.417 0 2.239-.029 2.465-.114a.52.52 0 0 0 .369-.311l.028-.085l.17-.539c.029-.085-.028-.142-.142-.142l-.906.057c-.596.029-1.077.057-1.418.057c-.651 0-1.076-.057-1.332-.142c-.368-.142-.538-.397-.51-.822l2.863-.368c1.275-.17 2.154-.567 2.579-1.19l-.992 3.315c-.028.057 0 .114.028.142c.029.028.085.057.199.057h1.19c.198 0 .283-.114.312-.199l1.048-3.656c.142-.481.567-.708 1.36-.708c.71 0 1.22 0 1.56.028h.028c.057 0 .17-.028.255-.17l.17-.51c0-.085 0-.17-.057-.227M4.841 13.73c-.368.057-.907.085-1.587.085c-1.219 0-1.729-.255-1.587-.737c.113-.34.425-.567.935-.624l2.75-.368zm12.669-2.95q-.17.553-1.616.766l-2.295.311l.056-.198c.199-.624.454-1.02.794-1.247q.51-.34 1.7-.34c1.05.028 1.503.255 1.36.708Z"]},"asus":{"label":"ASUS","viewBox":"0 0 24 24","paths":["M23.904 10.788V9.522h-4.656c-.972 0-1.41.6-1.482 1.182v.018v-1.2h-1.368v1.266h1.362zm-6.144.456l-1.368-.078v1.458c0 .456-.228.594-1.02.594H14.28c-.654 0-.93-.186-.93-.594v-1.596l-1.386-.102v1.812h-.03c-.078-.528-.276-1.14-1.596-1.23L6 11.22c0 .666.474 1.062 1.218 1.14l3.024.306c.24.018.414.09.414.288c0 .216-.18.24-.456.24H5.946V11.22l-1.386-.09v3.348h5.646c1.26 0 1.662-.654 1.722-1.2h.03c.156.864.912 1.2 2.19 1.2h1.41c1.494 0 2.202-.456 2.202-1.524zm4.398.258l-4.338-.258c0 .666.438 1.11 1.182 1.17l3.09.24c.24.018.384.078.384.276c0 .186-.168.258-.516.258h-4.212v1.29h4.302c1.356 0 1.95-.474 1.95-1.554c0-.972-.534-1.338-1.842-1.422m-10.194-1.98h1.386v1.266h-1.386zM3.798 11.07l-1.506-.15L0 14.478h1.686zm7.914-1.548h-4.23c-.984 0-1.416.612-1.518 1.2v-1.2H3.618c-.33 0-.486.102-.642.33l-.648.936h9.384Z"]},"samsung":{"label":"Samsung","viewBox":"0 0 24 24","paths":["m19.817 10.28l.046 2.694h-.023l-.78-2.693h-1.283v3.392h.848l-.046-2.785h.023l.836 2.785h1.227v-3.392zm-16.15 0l-.641 3.428h.928l.47-3.118h.023l.459 3.118h.916l-.63-3.427zm5.181 0l-.424 2.614h-.023l-.424-2.613H6.58l-.069 3.427h.86l.023-3.083h.011l.573 3.083h.871l.573-3.083h.023l.023 3.083h.86l-.08-3.427zm-7.266 2.454a.5.5 0 0 1 .011.252c-.023.114-.103.229-.332.229c-.218 0-.344-.126-.344-.31v-.332H0v.264c0 .768.607.997 1.25.997c.618 0 1.134-.218 1.214-.78c.046-.298.012-.492 0-.561c-.16-.722-1.467-.929-1.559-1.33a.5.5 0 0 1 0-.183c.023-.115.104-.23.31-.23s.32.127.32.31v.206h.86v-.24c0-.745-.676-.86-1.157-.86c-.608 0-1.112.206-1.204.757a1.04 1.04 0 0 0 .012.458c.137.71 1.364.917 1.536 1.352m11.152 0c.034.08.022.184.011.253c-.023.114-.103.229-.332.229c-.218 0-.344-.126-.344-.31v-.332h-.917v.264c0 .756.596.985 1.238.985c.619 0 1.123-.206 1.203-.779c.046-.298.012-.481 0-.562c-.137-.71-1.433-.928-1.524-1.318a.5.5 0 0 1 0-.183c.023-.115.103-.23.31-.23c.194 0 .32.127.32.31v.206h.848v-.24c0-.745-.665-.86-1.146-.86c-.607 0-1.1.195-1.192.757c-.023.149-.023.286.012.458c.137.71 1.34.905 1.513 1.352m2.888.459c.24 0 .31-.16.332-.252c.012-.035.012-.092.012-.126V10.28h.87v2.464c0 .069 0 .195-.01.23c-.058.641-.562.847-1.193.847c-.63 0-1.134-.206-1.192-.848c0-.034-.011-.16-.011-.229V10.28h.87v2.533c0 .046 0 .091.012.126c0 .091.07.252.31.252m7.152-.034c.252 0 .332-.16.355-.253c.011-.034.011-.091.011-.126v-.493h-.355v-.504H24v.917c0 .069 0 .115-.011.23c-.058.63-.597.847-1.204.847s-1.146-.217-1.203-.848c-.012-.114-.012-.16-.012-.229v-1.444c0-.057.012-.172.012-.23c.08-.641.596-.847 1.203-.847s1.135.206 1.203.848c.012.103.012.229.012.229v.115h-.86v-.195s0-.08-.011-.126c-.012-.08-.08-.252-.344-.252c-.252 0-.32.16-.344.252c-.011.045-.011.103-.011.16v1.57c0 .046 0 .092.011.126c0 .092.092.253.333.253"]},"toshiba":{"label":"Toshiba","viewBox":"0 0 24 24","paths":["M5.174 10.172c-1.065 0-1.578.187-1.65 1.148a9 9 0 0 0-.022.68c0 .218.004.451.021.68c.073.96.586 1.148 1.65 1.148s1.58-.188 1.653-1.148c.018-.229.022-.462.022-.68c0-.217-.005-.451-.022-.68c-.073-.96-.588-1.148-1.652-1.148m3.79 0c-.41 0-.82.04-.985.121c-.322.156-.545.38-.545 1.02c0 .375.1.654.293.796c.281.21.553.23 1.31.27c.305.016.47.078.47.34c0 .332-.294.332-.564.332c-.28 0-.366-.025-.46-.096c-.084-.063-.105-.176-.106-.348h-.95c0 .487.01.884.47 1.084c.41.18 1.67.18 2.048.014c.328-.145.563-.337.563-.994c0-.455-.091-.735-.44-.941c-.248-.147-.945-.17-1.298-.192c-.258-.016-.356-.11-.356-.338c0-.297.285-.308.53-.308c.202 0 .34.018.439.105c.038.039.086.099.088.307h.947c0-.408-.014-.848-.455-1.051c-.175-.08-.587-.121-.998-.121zm2.206.062v3.532h.996v-1.362h1.156v1.362h.996v-3.532h-.996v1.29h-1.156v-1.29zm4.023 0v3.532h1.002v-3.532zm1.891 0v3.532h1.887c.869 0 1.162-.376 1.162-.952c0-.401-.092-.755-.643-.894c.444-.114.574-.379.574-.762c0-.776-.487-.924-1.181-.924zm4.373 0l-1.068 3.532h1.037l.187-.655h1.16l.19.655H24l-1.07-3.532zM0 10.236v.881h1.055v2.65H2.11v-2.65h1.055v-.88zm5.174.762c.418 0 .633.063.66.607c.004.085.01.201.01.395c0 .195-.006.31-.01.395c-.027.544-.242.607-.66.607s-.633-.063-.66-.607A8 8 0 0 1 4.506 12c0-.194.003-.31.008-.395c.027-.544.242-.607.66-.607m12.906.045h.69c.18 0 .293.085.293.291c0 .176-.112.285-.293.285h-.69zm4.111.064h.006l.354 1.22h-.713zm-4.11 1.207h.689c.279 0 .337.124.337.323s-.11.32-.337.32h-.69z"]},"fujitsu":{"label":"Fujitsu","viewBox":"0 0 24 24","paths":["M16.56 3c-2.41 0-4.52 1.24-5.88 2.97v3.79c1.82-5.05 5.88-4.68 5.88-4.68c2.94 0 5.28 2.3 5.28 5.12c0 2.84-2.34 5.13-5.28 5.13a5.32 5.32 0 0 1-3.72-1.5l-2.56-2.8a6.06 6.06 0 0 0-4.25-1.71C2.7 9.32 0 11.93 0 15.16C0 18.4 2.7 21 6.03 21c1.87 0 3.55-.81 4.65-2.11v-3.03c-1.8 3.43-4.65 3.06-4.65 3.06c-2.13 0-3.86-1.68-3.86-3.76c0-2.06 1.73-3.74 3.86-3.74c1.06 0 2.02.42 2.72 1.08l2.56 2.81a7.5 7.5 0 0 0 5.25 2.12c4.11 0 7.44-3.24 7.44-7.23S20.67 3 16.56 3"]},"panasonic":{"label":"Panasonic","viewBox":"0 0 24 24","paths":["M3.157 11.485a1.254 1.254 0 0 0-1.18-1.324H0v3.58h1.084v-1.1h.66q.25 0 .496-.059c.497-.103.87-.52.917-1.025zm-1.081.005a.35.35 0 0 1-.337.301c-.081.007-.15.007-.23.007h-.425v-.777h.632a.36.36 0 0 1 .36.326a.7.7 0 0 1 0 .143m3.678 1.45c0-.278-.01-.51-.01-.786a1.7 1.7 0 0 0-.057-.42a.67.67 0 0 0-.332-.43a1 1 0 0 0-.316-.118a2.6 2.6 0 0 0-1.065-.02q-.15.023-.29.082a.77.77 0 0 0-.455.5a.6.6 0 0 0-.024.261a.1.1 0 0 0 .014.048l.86.02a.4.4 0 0 1 .025-.153a.26.26 0 0 1 .162-.162a.5.5 0 0 1 .342 0a.23.23 0 0 1 .156.157a.15.15 0 0 1-.02.13a.2.2 0 0 1-.1.078l-.074.024q-.17.045-.343.075a7 7 0 0 0-.276.05a3 3 0 0 0-.365.095a.8.8 0 0 0-.295.173a.62.62 0 0 0-.205.393a.8.8 0 0 0 .012.3a.71.71 0 0 0 .51.54c.276.083.573.067.84-.044a.83.83 0 0 0 .344-.248l.057.176q.019.048.051.087h.948a.4.4 0 0 1-.068-.207q-.02-.3-.026-.6m-.956-.088a.4.4 0 0 1-.067.193a.4.4 0 0 1-.182.145a.6.6 0 0 1-.21.054a.5.5 0 0 1-.163-.013a.24.24 0 0 1-.12-.074a.2.2 0 0 1-.057-.106a.17.17 0 0 1 .064-.174a.3.3 0 0 1 .105-.063q.142-.053.288-.093q.177-.052.342-.13a1 1 0 0 1 0 .261M8.06 11.14a1.04 1.04 0 0 0-.755.054a1.7 1.7 0 0 0-.393.262l-.023-.27H5.97v2.56h.982v-1.42a.4.4 0 0 1 .06-.222a.383.383 0 0 1 .482-.16c.081.032.142.1.167.183q.02.065.02.131v1.484h1.01V12.09a1.2 1.2 0 0 0-.06-.394a.82.82 0 0 0-.572-.558zm5.95 1.25a1.1 1.1 0 0 0-.42-.23l-.106-.03a5 5 0 0 0-.58-.123a2 2 0 0 1-.156-.03a.3.3 0 0 1-.068-.024a.117.117 0 0 1-.059-.152v-.008a.22.22 0 0 1 .131-.105a.5.5 0 0 1 .316 0c.107.03.178.133.17.244h.902a.9.9 0 0 0-.055-.31a.55.55 0 0 0-.184-.255a.9.9 0 0 0-.242-.138a1.2 1.2 0 0 0-.262-.073a2.6 2.6 0 0 0-.642-.037a2 2 0 0 0-.366.054a1.1 1.1 0 0 0-.444.211a.7.7 0 0 0-.28.526a.7.7 0 0 0 .052.316a.68.68 0 0 0 .393.393q.135.054.278.082l.554.104q.105.016.205.051c.06.018.103.07.113.131a.19.19 0 0 1-.052.176a.3.3 0 0 1-.17.086a.5.5 0 0 1-.262-.025a.4.4 0 0 1-.105-.06a.26.26 0 0 1-.089-.132a.4.4 0 0 1-.02-.138h-.932v.055a.77.77 0 0 0 .256.555a1 1 0 0 0 .426.24c.33.098.676.12 1.014.065q.241-.035.455-.148a1 1 0 0 0 .176-.118a.78.78 0 0 0 .246-.852a.63.63 0 0 0-.193-.302zm6.198-2.226h.957v.676h-.957zm0 1.024h.957v2.558h-.957zm2.872 1.505a1 1 0 0 1-.018.154a.4.4 0 0 1-.096.2a.3.3 0 0 1-.185.097a.36.36 0 0 1-.316-.1a.53.53 0 0 1-.152-.26a1.17 1.17 0 0 1 .012-.703a.4.4 0 0 1 .178-.232a.36.36 0 0 1 .407.017c.092.068.153.17.17.284h.874a.8.8 0 0 0-.09-.417a1.12 1.12 0 0 0-.724-.564a1.7 1.7 0 0 0-.806-.02c-.48.094-.863.456-.984.93a1.4 1.4 0 0 0-.03.621q.034.226.151.42c.095.171.227.32.385.435c.19.148.416.24.655.262q.27.03.538-.025a1.24 1.24 0 0 0 .685-.38a.93.93 0 0 0 .263-.719zm-3.704-1.553a1.04 1.04 0 0 0-.755.054a1.7 1.7 0 0 0-.393.262l-.03-.27h-.919v2.56h.984v-1.429a.43.43 0 0 1 .06-.22a.39.39 0 0 1 .484-.16c.08.032.14.1.164.182a.5.5 0 0 1 .021.14v1.483h1.016V12.09a1.2 1.2 0 0 0-.06-.394a.82.82 0 0 0-.572-.558zm-7.879 1.8c0-.278-.01-.51-.012-.786q0-.214-.054-.42a.68.68 0 0 0-.333-.43a1 1 0 0 0-.315-.118a2.6 2.6 0 0 0-1.067-.02q-.15.023-.289.082a.77.77 0 0 0-.456.5a.6.6 0 0 0-.025.261a.2.2 0 0 0 .015.048l.86.02a.4.4 0 0 1 .024-.153a.26.26 0 0 1 .163-.162a.5.5 0 0 1 .342 0a.23.23 0 0 1 .156.157a.15.15 0 0 1-.02.13a.2.2 0 0 1-.099.078l-.075.024q-.17.045-.343.075a6 6 0 0 0-.274.05a3 3 0 0 0-.366.095a.8.8 0 0 0-.296.173a.62.62 0 0 0-.21.393a.8.8 0 0 0 .012.3c.056.26.252.468.508.54c.277.083.575.067.842-.044a.8.8 0 0 0 .335-.245q.025.087.057.173a.3.3 0 0 0 .052.087h.948a.4.4 0 0 1-.054-.207a14 14 0 0 1-.026-.6m-.97-.084a.44.44 0 0 1-.07.19a.37.37 0 0 1-.167.144a.7.7 0 0 1-.205.054a.5.5 0 0 1-.175-.015a.25.25 0 0 1-.122-.073a.2.2 0 0 1-.055-.105a.17.17 0 0 1 .057-.17a.3.3 0 0 1 .105-.063a5 5 0 0 1 .288-.093q.177-.053.344-.13q.015.13 0 .261m5.483-1.72a1.9 1.9 0 0 0-.577 0a1.33 1.33 0 0 0-.747.371a1.2 1.2 0 0 0-.383.798c-.02.185-.003.372.048.551c.073.278.24.522.47.693c.147.117.32.197.504.235c.26.055.527.055.787 0a1.2 1.2 0 0 0 .507-.235c.23-.17.396-.415.468-.693a1.4 1.4 0 0 0 .05-.55a1.2 1.2 0 0 0-.383-.799a1.33 1.33 0 0 0-.743-.37zm.06 1.814a.39.39 0 0 1-.513.193a.37.37 0 0 1-.194-.193a1 1 0 0 1-.072-.246a1.4 1.4 0 0 1 .012-.515a.7.7 0 0 1 .1-.247a.374.374 0 0 1 .622 0a.6.6 0 0 1 .105.247q.052.257.01.515a1 1 0 0 1-.07.246"]},"lg":{"label":"LG","viewBox":"0 0 24 24","paths":["M14.522 14.078h3.27v1.33h-4.847v-6.83h1.577zm6.74-1.274h1.284v1.195c-.236.09-.698.18-1.137.18c-1.42 0-1.893-.721-1.893-2.186c0-1.398.45-2.221 1.869-2.221c.791 0 1.24.248 1.612.722l.982-.903c-.6-.855-1.646-1.114-2.629-1.114c-2.208 0-3.368 1.205-3.368 3.504c0 2.288 1.047 3.528 3.358 3.528c1.06 0 2.096-.27 2.66-.665V11.53h-2.739v1.274zM5.291 6.709a5.29 5.29 0 1 1 0 10.582a5.291 5.291 0 1 1 0-10.582m3.16 8.457a4.45 4.45 0 0 0 1.31-3.161v-.242l-.22.001H6.596v.494h2.662l-.001.015a3.985 3.985 0 0 1-3.965 3.708a3.95 3.95 0 0 1-2.811-1.165a3.95 3.95 0 0 1-1.164-2.811c0-1.061.414-2.059 1.164-2.81a3.95 3.95 0 0 1 2.81-1.164l.252.003v-.495l-.251-.003a4.475 4.475 0 0 0-4.47 4.469c0 1.194.465 2.316 1.309 3.161a4.44 4.44 0 0 0 3.16 1.31a4.44 4.44 0 0 0 3.162-1.31m-2.91-1.297V9.644H5.04v4.72h1.556v-.495zm-1.265-3.552a.676.676 0 1 0-.675.674a.676.676 0 0 0 .675-.674"]},"huawei":{"label":"Huawei","viewBox":"0 0 24 24","paths":["M3.67 6.14S1.82 7.91 1.72 9.78v.35c.08 1.51 1.22 2.4 1.22 2.4c1.83 1.79 6.26 4.04 7.3 4.55c0 0 .06.03.1-.01l.02-.04v-.04C7.52 10.8 3.67 6.14 3.67 6.14M9.65 18.6c-.02-.08-.1-.08-.1-.08l-7.38.26c.8 1.43 2.15 2.53 3.56 2.2c.96-.25 3.16-1.78 3.88-2.3c.06-.05.04-.09.04-.09zm.08-.78C6.49 15.63.21 12.28.21 12.28c-.15.46-.2.9-.21 1.3v.07c0 1.07.4 1.82.4 1.82c.8 1.69 2.34 2.2 2.34 2.2c.7.3 1.4.31 1.4.31c.12.02 4.4 0 5.54 0c.05 0 .08-.05.08-.05v-.06c0-.03-.03-.05-.03-.05M9.06 3.19a3.42 3.42 0 0 0-2.57 3.15v.41c.03.6.16 1.05.16 1.05c.66 2.9 3.86 7.65 4.55 8.65c.05.05.1.03.1.03a.1.1 0 0 0 .06-.1c1.06-10.6-1.11-13.42-1.11-13.42c-.32.02-1.19.23-1.19.23m8.299 2.27s-.49-1.8-2.44-2.28c0 0-.57-.14-1.17-.22c0 0-2.18 2.81-1.12 13.43c.01.07.06.08.06.08c.07.03.1-.03.1-.03c.72-1.03 3.9-5.76 4.55-8.64c0 0 .36-1.4.02-2.34m-2.92 13.07s-.07 0-.09.05c0 0-.01.07.03.1c.7.51 2.85 2 3.88 2.3c0 0 .16.05.43.06h.14c.69-.02 1.9-.37 3-2.26l-7.4-.25zm7.83-8.41c.14-2.06-1.94-3.97-1.94-3.98c0 0-3.85 4.66-6.67 10.8c0 0-.03.08.02.13l.04.01h.06c1.06-.53 5.46-2.77 7.28-4.54c0 0 1.15-.93 1.21-2.42m1.52 2.14s-6.28 3.37-9.52 5.55c0 0-.05.04-.03.11c0 0 .03.06.07.06c1.16 0 5.56 0 5.67-.02c0 0 .57-.02 1.27-.29c0 0 1.56-.5 2.37-2.27c0 0 .73-1.45.17-3.14"]}};
  function manufacturerFor(row) {
    const reported=text(row.manufacturer).trim();
    const valid=reported&&!/^(?:unknown|not reported|not available|n\/a|none|oem|system manufacturer|to be filled by o\.?e\.?m\.?|[-—]+)$/i.test(reported);
    const aliases=[['dell',/\bdell\b/i],['apple',/\bapple\b/i],['hp',/\bhp\b|hewlett[ -]?packard/i],['lenovo',/\blenovo\b/i],['microsoft',/\bmicrosoft\b/i],['acer',/\bacer\b/i],['asus',/\basus\b|asustek/i],['samsung',/\bsamsung\b/i],['toshiba',/\btoshiba\b/i],['fujitsu',/\bfujitsu\b/i],['panasonic',/\bpanasonic\b/i],['lg',/\blg\b/i],['huawei',/\bhuawei\b/i]];
    if(valid){const match=aliases.find(([,pattern])=>pattern.test(reported));return {key:match?match[0]:null,label:match?manufacturerMarks[match[0]].label:reported,basis:'Reported manufacturer'};}
    if(row.support_ref&&row.support_ref.sourceKey==='aws'||/^AWS\b/i.test(row.source||''))return null;
    const model=text(row.model),type=text(row.type);
    const match=aliases.find(([,pattern])=>pattern.test(model));
    const inferred=match?match[0]:/\b(?:MacBook|iMac|Mac mini|Mac Pro|Mac Studio|iPad|iPhone)\b/i.test(model+' '+type)?'apple':/\b(?:Latitude|OptiPlex|Precision|Inspiron|Vostro|PowerEdge|XPS)\b/i.test(model)?'dell':/\b(?:ThinkPad|ThinkCentre|ThinkStation|IdeaPad)\b/i.test(model)?'lenovo':/\b(?:EliteBook|ProBook|ZBook|EliteDesk|ProDesk)\b/i.test(model)?'hp':/\bSurface\b/i.test(model)?'microsoft':/\b(?:ZenBook|VivoBook)\b/i.test(model)?'asus':/\b(?:TravelMate|Aspire)\b/i.test(model)?'acer':/^SM-[A-Z0-9]/i.test(model)?'samsung':null;
    return inferred?{key:inferred,label:manufacturerMarks[inferred].label,basis:'Identified from model'}:null;
  }
  function manufacturerIcon(brand,fallback) {
    const mark=brand&&manufacturerMarks[brand.key];
    if(!mark)return '<span class="ms iv360-device-icon" aria-hidden="true">'+fallback+'</span>';
    return '<span class="iv360-device-icon iv360-brand-icon" data-manufacturer="'+esc(brand.key)+'"><svg viewBox="'+mark.viewBox+'" role="img" aria-label="'+esc(brand.label)+' logo" focusable="false">'+mark.paths.map(d=>'<path fill="currentColor" d="'+d+'"/>').join('')+'</svg></span>';
  }
  function shortDate(value) {
    if(!value)return '';
    const date=new Date(value);
    return Number.isFinite(date.getTime())?date.toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric',timeZone:'UTC'}):'';
  }
  function observed(records) {
    const dates=records.map(r=>r.observedAt).filter(v=>v&&Number.isFinite(Date.parse(v)));
    return dates.length?shortDate(dates.sort((a,b)=>Date.parse(b)-Date.parse(a))[0]):'';
  }
  function sectionState(section) {
    return {ok:'Evidence available',partial:'Partial evidence',empty:'No evidence',denied:'Permission required',unavailable:'Source unavailable'}[section&&section.status]||'Source unavailable';
  }
  function statusSummary(detail) {
    const specs=[['inventory','Compliance','policy'],['encryption','Encryption','lock'],['warranty','Warranty','verified_user'],['zcc','Zscaler','cloud_done']];
    return specs.map(([key,label,icon])=>{
      const section=detail&&detail[key],rows=recordsFor(section);
      const item={key,label,icon,value:'Unknown',tone:'muted',note:sectionState(section)};
      if(!rows.length)return item;
      const partial=section.status==='partial'?'Partial evidence · ':'';
      if(key==='inventory') {
        const names={compliant:'Compliant',noncompliant:'Noncompliant',ingraceperiod:'In grace',ingrace:'In grace',grace:'In grace'};
        const compliance=r=>names[text(r.compliance).toLowerCase().replace(/[^a-z]/g,'')];
        // Missing values stay in source details; only reported states can disagree.
        const reported=rows.filter(r=>compliance(r));
        const values=unique(reported.map(compliance));
        item.value=values.length>1?'Mixed statuses':values[0]||'Not reported';
        item.tone=values.length>1?'warn':item.value==='Compliant'?'good':item.value==='Noncompliant'?'bad':item.value==='In grace'?'warn':'muted';
        item.note=partial+(values.length>1?values.join(' / '):observed(reported)?'Snapshot '+observed(reported):reported.length?'Inventory source':'No reported compliance value');
      } else if(key==='encryption') {
        const known=unique(rows.map(r=>r.encrypted).filter(v=>typeof v==='boolean'));
        const preferred=rows.filter(r=>r.preferred),chosen=preferred.length?preferred:rows;
        const values=unique(chosen.map(r=>typeof r.encrypted==='boolean'?r.encrypted:null));
        if(section.conflict||known.length>1){item.value='Sources disagree';item.tone='warn';item.note='Compare preferred source and dates';}
        else {
          const value=values.length===1?values[0]:null;
          item.value=value===true?'Encrypted':value===false?'Not encrypted':'Unknown';
          item.tone=value===true?'good':value===false?'bad':'muted';
          const escrow=unique(chosen.map(r=>r.recoveryKeyEscrowed));
          item.note=partial+(escrow.length===1&&escrow[0]===true?'Key escrowed':escrow.length===1&&escrow[0]===false?'Key not escrowed':'Escrow not reported')+(observed(chosen)?' · '+observed(chosen):'');
        }
      } else if(key==='warranty') {
        const values=unique(rows.map(r=>['active','expired','canceled'].includes(r.coverage)?r.coverage:'unknown'));
        const value=values.length===1?values[0]:'mixed';
        item.value={active:'Covered',expired:'Expired',canceled:'Canceled',unknown:'Unknown',mixed:'Review coverage'}[value];
        item.tone=value==='active'?'good':['expired','canceled','mixed'].includes(value)?'warn':'muted';
        item.note=partial+(rows.length===1&&shortDate(rows[0].endDate)?'Recorded expiry '+shortDate(rows[0].endDate):rows.length+' coverage record'+(rows.length===1?'':'s'));
      } else {
        const confirmed=rows.filter(r=>r.match&&r.match.status==='confirmed');
        if(confirmed.length!==1||rows.length!==1){item.value=rows.length>1?'Review enrollments':'Association unverified';item.tone='warn';item.note=rows.length+' enrollment record'+(rows.length===1?'':'s')+' · Open source details';}
        else {
          const snapshot=confirmed[0].snapshot||{};
          item.value=snapshot.registration||'Registration unknown';
          item.tone='neutral';
          item.note=partial+'Stored registration'+(shortDate(snapshot.observedAt)?' · '+shortDate(snapshot.observedAt):'')+'; connection unknown';
        }
      }
      return item;
    });
  }
  function selectGroup(groups,ref) {
    if(!ref||!ref.sourceKey)return null;
    const row=text(ref.rowId).trim(),native=text(ref.nativeId).trim();
    if(!row&&!native)return null;
    const matches=(groups||[]).filter(g=>(g.sourceRefs||[]).some(r=>r.sourceKey===ref.sourceKey&&(row?text(r.rowId)===row:text(r.nativeId)===native)));
    return matches.length===1&&matches[0].deviceKey?matches[0]:null;
  }
  function reviewGroups(rows) {
    return {terminated:rows.filter(r=>r.user_status==='Terminated'),unassigned:rows.filter(r=>!r.user_key),unmatched:rows.filter(r=>r.user_key&&r.user_status===null)};
  }
  function safeLink(href,origin) {
    try{const u=new URL(href,origin);return u.origin===origin&&!u.username&&!u.password&&['/IT_Inventory_App.html','/identity-diag.html','/zscaler-command-center.html','/patch-status.html'].includes(u.pathname)?u.href:null;}catch(_){return null;}
  }
  function ownerQuery(row) {
    if(!row.user_key)return '';
    return row.support_ref&&row.support_ref.sourceKey==='kandji-mac'&&row.user_status!=='Active'&&row.user_raw?row.user_raw:row.user_key;
  }
  async function getJSON(path,signal,fetcher) {
    const response=await fetcher(path,{method:'GET',credentials:'same-origin',cache:'no-store',signal});
    if(response.status===401)throw Error('Your session has expired. Sign in again, then retry Device 360.');
    if(response.status===403)throw Error('People & Devices read permission is required for connected evidence. The selected inventory record remains available below.');
    if(!response.ok)throw Error('Connected device evidence is unavailable (HTTP '+response.status+'). Retry when the source is available.');
    let body;try{body=await response.json();}catch(_){throw Error('The device evidence service did not return a readable response.');}
    if(!body||typeof body!=='object'||Array.isArray(body))throw Error('The device evidence response was incomplete.');
    return body;
  }
  async function loadEvidence(row,signal,fetcher) {
    const q=ownerQuery(row),ref=row.support_ref;
    if(!q)return {localReason:'This record has no assigned person. Person-scoped evidence was not requested.'};
    if(!ref||!ref.sourceKey||(!text(ref.rowId)&&!text(ref.nativeId)))return {localReason:'This record has no stable source identifier. Connected evidence cannot be associated safely.'};
    const discovery=await getJSON('/api/identity/devices?q='+encodeURIComponent(q),signal,fetcher);
    if(!Array.isArray(discovery.deviceGroups))throw Error('Grouped device discovery is unavailable. Connected evidence was not requested.');
    const group=selectGroup(discovery.deviceGroups,ref);
    if(!group)throw Error('This source record could not be uniquely verified for the recorded owner. Recheck the assignment; no other device was selected.');
    const detail=await getJSON('/api/identity/device-detail?q='+encodeURIComponent(q)+'&deviceKey='+encodeURIComponent(group.deviceKey),signal,fetcher);
    if(detail.deviceKey!==group.deviceKey||!detail.device||!selectGroup([detail.device],ref))throw Error('The returned evidence did not match the selected source record. Reopen Device 360.');
    return {detail,q,group,discoveryUnavailable:discovery.unavailable||[]};
  }
  if(typeof module==='object'&&module.exports&&typeof document==='undefined'){module.exports={esc,selectGroup,reviewGroups,safeLink,ownerQuery,loadEvidence,truth,statusSummary,recordsFor,sectionState,manufacturerFor,manufacturerIcon};return;}

  const registry=new Map();let registryVersion=-1;
  const dialog=document.getElementById('iv360-dialog'),evidence=document.getElementById('iv360-evidence');
  const queue=document.getElementById('offboarding-review');
  let opener=null,controller=null,timeout=null,generation=0,selected=null,queueFilter='terminated',queuePage=1,queueSignature='';
  const labels={terminated:'Terminated owners',unassigned:'Unassigned',unmatched:'Owner not in HR'};
  const notes={terminated:'Devices still recorded against terminated employees. Review the assignment and return status.',unassigned:'No assigned user is recorded. This can include stock or shared equipment.',unmatched:'The recorded owner could not be joined to the loaded HR records. Review the identity match.'};
  function version(){return typeof DATA_VERSION==='number'?DATA_VERSION:0;}
  function action(row) {
    const v=version();if(registryVersion!==v){registry.clear();registryVersion=v;}
    const ref=row.support_ref||{};
    const key=JSON.stringify([v,ref.sourceKey,ref.rowId,ref.nativeId,row.serial,row.user_key,row.source]);
    registry.set(key,row);
    return '<button type="button" class="btn btn-ghost btn-sm iv360-action" data-device360="'+esc(key)+'" aria-label="Open Device 360 for '+esc(row.serial||row.model)+'">Device 360<span class="ms" aria-hidden="true">chevron_right</span></button>';
  }
  function sourceAction(table,record) {
    if(!record||!['endpoints','macbooks','intune','ipads','aws'].includes(table))return '';
    const ref=inventorySupportRef(table,record);
    const known=buildDeviceUniverse().find(r=>r.support_ref&&r.support_ref.sourceKey===ref.sourceKey&&(ref.rowId!=null?text(r.support_ref.rowId)===text(ref.rowId):ref.nativeId!=null&&text(r.support_ref.nativeId)===text(ref.nativeId)));
    if(known)return action(known);
    const raw=table==='endpoints'?(record['First/Last']||record['Currently Logged on Users']):table==='macbooks'||table==='ipads'?record['User']:table==='aws'?record['Username']:record['Primary user UPN'];
    return action({support_ref:ref,manufacturer:inventoryDeviceManufacturer(record),source:({endpoints:'ManageEngine',macbooks:'Kandji',intune:'Intune',ipads:'Kandji iPad',aws:'AWS'})[table],
      serial:record['Serial']||record['Serial number']||record['Service Tag']||record['WorkSpace ID']||record['Computer Name'],model:record['Model']||record['Compute'],
      user_raw:raw,user_key:typeof _diExtractUser==='function'?_diExtractUser(raw):raw,user_status:undefined,
      type:record['OS']||record['OS Name']||table,status:record['Compliance']||record['Status']||'Not reported'});
  }
  function navigateReview(filter) {
    if(typeof window.itamClearSearch==='function')window.itamClearSearch();
    document.querySelectorAll('#page-device-inventory select.filter-select').forEach(s=>{s.value='';});
    document.getElementById('di-filter-assignment').value=filter;
    if(typeof pages==='object')pages['device-inventory']=1;
    window.showPage('device-inventory');
  }
  function renderQueue() {
    if(!queue)return;
    const load=typeof inventoryLoadState==='object'?inventoryLoadState:null;
    if(!load||load.phase!=='ready'){queue.innerHTML='<p class="iv-empty">Loading inventory and HR records…</p>';queueSignature='';return;}
    if(['activeEmployees','terms'].some(k=>load.sources[k]!=='ok')){queue.innerHTML='<p class="iv-empty" role="status">HR records are unavailable. Ownership groups cannot be classified reliably. Reload after the HR source is available.</p>';queueSignature='';return;}
    const groups=reviewGroups(buildDeviceUniverse()),rows=groups[queueFilter];
    const failed=['endpoints','macbooks','intuneDevices','ipadDevices','awsWorkspaces'].filter(k=>load.sources[k]!=='ok');
    queuePage=Math.max(1,Math.min(queuePage,Math.ceil(rows.length/5)||1));
    const signature=JSON.stringify([version(),queueFilter,queuePage,failed]);if(signature===queueSignature)return;
    const focus=queue.contains(document.activeElement)?document.activeElement.getAttribute('data-queue-focus'):null;
    let h='<div class="iv-offboard-filters" role="group" aria-label="Ownership review category">'+Object.keys(labels).map(k=>'<button type="button" class="iv-offboard-filter" aria-pressed="'+(k===queueFilter)+'" data-review-filter="'+k+'" data-queue-focus="'+k+'">'+labels[k]+'<strong>'+groups[k].length.toLocaleString()+'</strong></button>').join('')+'</div>';
    h+='<div class="iv-offboard-caption"><p>'+notes[queueFilter]+'</p><button type="button" class="btn btn-ghost btn-sm" data-review-all data-queue-focus="all">View matching inventory<span class="ms" aria-hidden="true">chevron_right</span></button></div>';
    if(failed.length)h+='<p class="iv360-notice">Partial device inventory: '+esc(failed.join(', '))+'. Counts cover loaded records only.</p>';
    h+='<div class="iv-offboard-table"><table><thead><tr><th scope="col">Device / source</th><th scope="col">Recorded owner</th><th scope="col">Review</th></tr></thead><tbody>';
    const slice=rows.slice((queuePage-1)*5,queuePage*5);
    h+=slice.length?slice.map(r=>'<tr><td><strong>'+esc(present(r.serial))+'</strong><small>'+esc(present(r.model))+' · '+esc(r.source)+'</small></td><td>'+esc(r.user_key?(r.user_name||r.user_raw||'Not reported'):'Unassigned')+'<small>'+esc(r.user_status||(!r.user_key?'No assigned user':'Not matched to HR'))+'</small></td><td>'+action(r)+'</td></tr>').join(''):'<tr><td colspan="3" class="iv-offboard-empty">No matching records in the loaded data.</td></tr>';
    h+='</tbody></table></div><div class="iv-offboard-footer"><span aria-live="polite">'+rows.length.toLocaleString()+' source records'+(rows.length?' · Showing '+((queuePage-1)*5+1)+'–'+Math.min(queuePage*5,rows.length):'')+'</span><div><button type="button" class="btn btn-ghost btn-sm" data-review-page="-1" data-queue-focus="previous"'+(queuePage===1?' disabled':'')+'>Previous</button><button type="button" class="btn btn-ghost btn-sm" data-review-page="1" data-queue-focus="next"'+(queuePage*5>=rows.length?' disabled':'')+'>Next</button></div></div>';
    queue.innerHTML=h;queueSignature=signature;
    if(focus){const target=Array.from(queue.querySelectorAll('[data-queue-focus]')).find(n=>n.getAttribute('data-queue-focus')===focus&&!n.disabled);if(target)target.focus({preventScroll:true});}
  }
  function kv(label,value){return '<div><dt>'+esc(label)+'</dt><dd>'+esc(present(value))+'</dd></div>';}
  function localRecord(row) {
    const state=row.user_status||(!row.user_key?'No assigned user':row.user_status===undefined?'HR not checked':'Not matched to HR');
    const tone=state==='Active'?'good':state==='Terminated'?'bad':'muted';
    const owner=row.user_key?(row.user_name||row.user_raw||'Not reported'):'Unassigned';
    const icon=/aws/i.test(row.source)?'cloud':/ipad|tablet|phone/i.test(row.type)?'tablet_mac':'laptop_windows';
    const brand=manufacturerFor(row);
    return '<div class="iv360-identity">'+manufacturerIcon(brand,icon)+'<div><strong>'+esc(present(row.model))+'</strong><span>'+esc([brand&&brand.label,row.source,present(row.type)].filter(Boolean).join(' · '))+'</span></div></div><div class="iv360-owner"><span class="ms" aria-hidden="true">person</span><strong>'+esc(owner)+'</strong><span class="iv360-owner-state" data-tone="'+tone+'">'+esc(state)+'</span></div><p class="iv360-snapshot-note">Inventory status: '+esc(present(row.status))+'. Source snapshots; check dates before acting.</p>';
  }
  function recordDetails(row) {
    const ref=row.support_ref||{};
    const brand=manufacturerFor(row);
    return '<details class="iv360-disclosure"><summary><span class="ms iv360-detail-icon" aria-hidden="true">assignment_ind</span><span class="iv360-detail-title">Assignment & record</span><span class="iv360-detail-meta">'+esc(row.source)+'</span><span class="ms iv360-chevron" aria-hidden="true">expand_more</span></summary><div class="iv360-disclosure-body"><dl class="iv360-facts">'+kv('Manufacturer',brand&&brand.label)+kv('Manufacturer source',brand&&brand.basis)+kv('Recorded owner',row.user_key?(row.user_name||row.user_raw||'Not reported'):'Unassigned')+kv('HR match',row.user_status||(!row.user_key?'No assigned user':row.user_status===undefined?'Not checked in consolidated inventory':'Not matched to HR'))+kv('Inventory status',row.status)+kv('Manager',row.manager)+kv('Source record',ref.rowId)+kv('Serial / identifier',row.serial)+'</dl></div></details>';
  }
  function evidenceSection(title,icon,section,fields) {
    section=section||{};
    const state=section.status||'unavailable',allowed=['ok','partial','empty'].includes(state);
    const count=recordsFor(section).length;
    const stateLabel=state==='ok'?count+' source record'+(count===1?'':'s'):sectionState(section);
    let h='<details class="iv360-disclosure"><summary><span class="ms iv360-detail-icon" aria-hidden="true">'+icon+'</span><span class="iv360-detail-title">'+title+'</span><span class="iv360-detail-meta"'+(['partial','denied','unavailable'].includes(state)?' data-tone="warn"':'')+'>'+esc(stateLabel)+'</span><span class="ms iv360-chevron" aria-hidden="true">expand_more</span></summary><div class="iv360-disclosure-body">';
    if(section.reason)h+='<p class="iv360-note">'+esc(section.reason)+'</p>';
    (section.sources||[]).filter(s=>['denied','partial','unavailable'].includes(s.status)).forEach(s=>{h+='<p class="iv360-notice">'+esc(s.source)+': '+esc(s.status)+(s.reason?' · '+esc(s.reason):'')+'</p>';});
    if(allowed&&(section.records||[]).length){
      h+=section.records.map(r=>'<article class="iv360-source-record"><strong>'+esc(r.source||title)+'</strong>'+(r.preferred?'<span class="iv360-preferred">Preferred source</span>':'')+'<dl class="iv360-facts">'+fields(r)+'</dl></article>').join('');
    }else h+='<p class="iv360-note">'+(state==='denied'?'Read permission is required for this source.':state==='unavailable'?'This source could not be read.':'No selected-device evidence reported.')+'</p>';
    return h+'</div></details>';
  }
  function renderDetail(result,row) {
    const insights=window.Inventory360Insights?Inventory360Insights.placeholder(row,result):'';
    if(result.localReason)return '<p class="iv360-notice">'+esc(result.localReason)+'</p>'+insights;
    const d=result.detail;
    let h='<section class="iv360-status-grid" aria-label="Key device statuses">'+statusSummary(d).map(s=>'<div class="iv360-stat" data-tone="'+s.tone+'"><span class="iv360-stat-label"><span class="ms" aria-hidden="true">'+s.icon+'</span>'+s.label+'</span><strong>'+esc(s.value)+'</strong><small>'+esc(s.note)+'</small></div>').join('')+'</section>';
    const limitations=[...(d.limitations||[]),...result.discoveryUnavailable.map(s=>'Assigned inventory source unavailable: '+s)];
    if(limitations.length)h+='<p class="iv360-compact-warning"><span class="ms" aria-hidden="true">info</span>Some evidence is limited. Review flagged sources and read notes below.</p>';
    const support=new URL('/identity-diag.html',location.origin);support.searchParams.set('q',result.q);support.searchParams.set('device',result.group.deviceKey);support.searchParams.set('view','devices');
    const zccLinks=(d.links||[]).filter(l=>l.kind==='zcc');
    const links=[{label:'People & Devices',href:support.href,icon:'devices'},...zccLinks.map((l,i)=>({...l,label:zccLinks.length===1?'Open Zscaler':'Zscaler enrollment '+(i+1),icon:'open_in_new'}))];
    h+='<nav class="iv360-links" aria-label="Selected device support">'+links.map(l=>{const href=safeLink(l.href,location.origin);return href?'<a class="btn btn-ghost btn-sm" href="'+esc(href)+'" target="_blank" rel="noopener"><span class="ms" aria-hidden="true">'+l.icon+'</span>'+esc(l.label)+'</a>':'';}).join('')+'</nav><h3 class="iv360-details-heading">Device insights<span>Expand to inspect</span></h3>'+insights;
    h+='<details class="iv360-disclosure iv360-source-group"><summary><span class="ms iv360-detail-icon" aria-hidden="true">database</span><span class="iv360-detail-title">Source evidence</span><span class="iv360-detail-meta">4 categories</span><span class="ms iv360-chevron" aria-hidden="true">expand_more</span></summary><div class="iv360-disclosure-body">';
    h+=evidenceSection('Inventory','inventory_2',d.inventory,r=>kv('Owner',r.owner)+kv('Ownership',r.ownership)+kv('Compliance',r.compliance)+kv('Last check-in',r.lastCheckin)+kv('Observed at',r.observedAt));
    h+=evidenceSection('Encryption','lock',d.encryption,r=>kv('Encrypted',truth(r.encrypted))+kv('Recovery key escrowed',truth(r.recoveryKeyEscrowed))+kv('Observed at',r.observedAt));
    h+=evidenceSection('Warranty','verified_user',d.warranty,r=>kv('Coverage',r.coverage)+kv('Association',r.association)+kv('Recorded expiry',r.endDate)+kv('Observed at',r.observedAt));
    h+=evidenceSection('Zscaler Client Connector','cloud_done',d.zcc,r=>{
      const s=r.snapshot||{},live=r.live||{};
      return kv('Association',r.match&&r.match.status)+kv('Association basis',r.match&&r.match.basis)+kv('UDID',r.udid)+kv('Stored agent version',s.agentVersion)+kv('Stored policy',s.policy)+kv('Stored registration',s.registration)+kv('Stored activity',s.reportedActivity)+kv('Snapshot observed',s.observedAt)+kv('Person lookup join',r.liveStatus)+kv('Lookup agent version',live.agentVersion)+kv('Lookup VPN state',live.vpnState)+kv('Lookup observed',live.observedAt);
    });
    h+='</div></details>';
    h+='<details class="iv360-disclosure iv360-read-notes"><summary><span class="ms iv360-detail-icon" aria-hidden="true">info</span><span class="iv360-detail-title">Read notes</span><span class="iv360-detail-meta">'+(limitations.length?limitations.length+' limitation'+(limitations.length===1?'':'s'):'Source context')+'</span><span class="ms iv360-chevron" aria-hidden="true">expand_more</span></summary><div class="iv360-disclosure-body"><p class="iv360-note">Evidence read '+esc(present(d.readAt))+' · Device association: '+esc(result.group.match&&result.group.match.status||'Not reported')+'</p>'+(limitations.length?'<div class="iv360-notice">'+limitations.map(s=>'<div>'+esc(s)+'</div>').join('')+'</div>':'')+(d.zdx?'<p class="iv360-note">ZDX experience: '+esc(d.zdx.reason||d.zdx.state||'Unavailable')+'</p>':'')+'</div></details>';
    return h;
  }
  async function readSelected(row) {
    if(controller)controller.abort();clearTimeout(timeout);const epoch=++generation;
    controller=new AbortController();const signal=controller.signal;timeout=setTimeout(()=>controller&&controller.abort(),20000);
    evidence.innerHTML='<p class="iv360-note" role="status">Reading selected-device evidence…</p>';
    try{
      const result=await loadEvidence(row,signal,window.fetch.bind(window));
      if(epoch!==generation||!dialog.open)return;evidence.innerHTML=renderDetail(result,row);
      if(window.Inventory360Insights)Inventory360Insights.mount(row,result);
    }catch(error){
      if(epoch!==generation||!dialog.open)return;
      evidence.innerHTML='<div class="iv360-notice" role="status">'+esc(error.name==='AbortError'?'Device evidence timed out. Retry when ready.':error.message)+'</div><button type="button" class="btn btn-ghost" data-device360-retry>Retry evidence</button>';
    }finally{if(epoch===generation){clearTimeout(timeout);controller=null;}}
  }
  function open(row,trigger) {
    if(!dialog)return;
    if(window.Inventory360Insights)Inventory360Insights.reset();
    if(!dialog.open)opener=trigger||document.activeElement;
    selected=row;document.getElementById('iv360-subtitle').textContent=present(row.serial);
    document.getElementById('iv360-record').innerHTML=localRecord(row);
    document.getElementById('iv360-context').innerHTML=recordDetails(row);
    dialog.querySelector('.iv360-content').scrollTop=0;
    if(!dialog.open)dialog.showModal();
    document.getElementById('iv360-close').focus({preventScroll:true});readSelected(row);
  }
  if(dialog){
    document.getElementById('iv360-close').addEventListener('click',()=>dialog.close());
    dialog.addEventListener('close',()=>{++generation;if(controller)controller.abort();clearTimeout(timeout);controller=null;selected=null;if(window.Inventory360Insights)Inventory360Insights.reset();evidence.innerHTML='';const returnTo=opener;opener=null;if(returnTo&&returnTo.isConnected)returnTo.focus({preventScroll:true});});
    dialog.addEventListener('click',event=>{if(event.target!==dialog)return;const r=dialog.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)dialog.close();});
  }
  document.addEventListener('click',event=>{
    const trigger=event.target.closest('[data-device360]');
    if(trigger){const row=registry.get(trigger.getAttribute('data-device360'));if(!row||registryVersion!==version()){if(typeof showToast==='function')showToast('Inventory changed. Reopen the device list.','warn');return;}open(row,trigger);return;}
    if(event.target.closest('[data-device360-retry]')&&selected){readSelected(selected);return;}
    if(!queue||!queue.contains(event.target))return;
    const filter=event.target.closest('[data-review-filter]'),page=event.target.closest('[data-review-page]');
    if(filter){queueFilter=filter.getAttribute('data-review-filter');queuePage=1;renderQueue();}
    else if(page){queuePage+=Number(page.getAttribute('data-review-page'));renderQueue();}
    else if(event.target.closest('[data-review-all]'))navigateReview(queueFilter);
  });
  window.Inventory360={action,sourceAction,renderQueue,open};
})();
