
// test OpenGL calls

#include <stdlib.h>
#include <stdio.h>
#include <GL/glut.h>


static void ReSizeGLScene (int width, int height)
{
    printf("resize to %d/%d\n", width, height);

    if (width < 1)
        width = 1;
    if (height < 1)
        height = 1;

    glViewport(0, 0, width, height);

    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();

    gluPerspective(45.0f, (GLfloat)width /(GLfloat)height, 0.1f, 100.0f);

    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
}


void InitGL ()
{
    glShadeModel(GL_SMOOTH);

    glClearColor(0.4f, 0.0f, 0.0f, 0.0f);

    glClearDepth(1.0f);
    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LEQUAL);

    glHint(GL_PERSPECTIVE_CORRECTION_HINT, GL_NICEST);
}


static void DrawGLScene ()
{
    //printf("draw...\n");
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    glLoadIdentity();

    glutSwapBuffers();
}



int main (int argc, char* argv[])
{
    printf("started\n");

    glutInit(&argc, argv);
    glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGB | GLUT_DEPTH);
    glutInitWindowSize(400, 400);
    glutInitWindowPosition(100, 100);
    glutCreateWindow(argv[0]);

    InitGL();

    glutDisplayFunc(DrawGLScene);
    glutIdleFunc(DrawGLScene);
    glutReshapeFunc(ReSizeGLScene);

    glutMainLoop();

    return 0;
}

