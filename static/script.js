
var like = document.getElementsByClassName("like")
function toggleLike() {
    for (var i = 0; i < like.length; i++) {
        like[i].style.color = "var(--fg-link)";
    }
}